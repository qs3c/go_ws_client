package e2ewebsocket

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/albert/ws_client/compressor"
	"github.com/albert/ws_client/encoder"
	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
)

type Conn struct {
	// 初始化需要提供的字段
	conn   *websocket.Conn
	hostId string
	config *Config

	sessionsMu sync.RWMutex
	sessions   map[SessionID]*Session

	// 握手状态相关
	// vers                uint16
	// cipherSuite         uint16
	// secureRenegotiation bool
	// curveID             CurveID
	// handshakes          int
	// isHandshakeComplete atomic.Bool
	// handshakeErr        error
	// handshakeFn         func(context.Context) error
	// handshakeMutex      sync.Mutex
	// in, out             halfConn
	// localFinished       [12]byte
	// remoteFinished      [12]byte

	// 连接状态相关
	// activeCall      atomic.Int32
	// closeNotifyErr  error
	// closeNotifySent bool

	// 缓冲区/队列相关
	// readQueue []readMsgItem
	msgChan chan readMsgItem
}

func NewSecureConn(wsconn *websocket.Conn, hostId string, config *Config) *Conn {
	c := &Conn{
		conn:     wsconn,
		hostId:   hostId,
		sessions: make(map[SessionID]*Session),
		config:   config,
		msgChan:  make(chan readMsgItem, 128),
	}
	go c.readLoop()
	return c
}

type readMsgItem struct {
	sessionId SessionID
	remoteId  string
	msgType   int
	msg       []byte
	err       error
}

type PingPongHandler func(string) error

func (c *Conn) ReadMessage() (int, []byte, error) {
	item, ok := <-c.msgChan
	if !ok {
		return 0, nil, errors.New("connection closed")
	}
	return item.msgType, item.msg, item.err
}

func (c *Conn) readLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("readLoop panic: %v", r)
		}
		c.sessionsMu.Lock()
		// 关闭所有 session 的握手通道，防止阻塞
		for _, s := range c.sessions {
			close(s.handshakeChan)
		}
		c.sessionsMu.Unlock()
		close(c.msgChan)
		log.Println("readLoop exited")
	}()

	for {
		// 这个函数主要处理消息分发
		// 进来先读一条数据再做打算
		msgType, msg, err := c.conn.ReadMessage()
		if err != nil {
			log.Printf("readLoop ReadMessage error: %v", err)
			c.msgChan <- readMsgItem{err: err}
			return
		}

		// 如果不是二进制类型的，正常传递给上层
		if msgType != websocket.BinaryMessage {
			c.msgChan <- readMsgItem{sessionId: "", remoteId: "", msgType: msgType, msg: msg, err: nil}
			continue
		}

		// 解析 msg
		typ := recordType(msg[0])
		senderId := string(bytes.TrimRight(msg[1:11], "\x00"))

		// 构造sessionId 并获取到对应的session
		sessionId := getSessionID(c.hostId, senderId)

		c.sessionsMu.Lock()
		session := c.sessions[sessionId]
		if session == nil {
			// session 创建逻辑应该在这里
			session = NewSession(sessionId, senderId, c)
			c.sessions[sessionId] = session
			// 被动创建的 Session，需要主动触发握手以响应对端（对称握手）
			go func(s *Session) {
				if err := s.Handshake(); err != nil {
					log.Printf("Passive handshake failed for session %s: %v", s.id, err)
				}
			}(session)
		}
		c.sessionsMu.Unlock()

		// 握手状态相关的校验，全部后置
		if session.in.err != nil {
			log.Printf("readLoop session error: %v", session.in.err)
			c.msgChan <- readMsgItem{err: session.in.err}
			return
		}

		handshakeComplete := session.isHandshakeComplete.Load()

		// 校验结束，开始解密
		data, err := session.in.decrypt(msg[11:])
		if err != nil {
			log.Printf("readLoop decrypt error: %v", err)
			session.in.setErrorLocked(errors.New("decrypt failed"))
			c.msgChan <- readMsgItem{err: err}
			return
		}

		// 处理不同类型的TLS记录
		switch typ {
		default:
			log.Printf("readLoop unexpected message type: %d", typ)
			session.in.setErrorLocked(errors.New("alertUnexpectedMessage"))
			c.msgChan <- readMsgItem{err: errors.New("alertUnexpectedMessage")}
			return

		// 处理 TLS 应用数据记录
		case recordTypeApplicationData:
			expected := false // readLoop 不应该知道 expectChangeCipherSpec，默认为 false
			// 但是这里有个问题，ccs 的确会影响下一次解密，但是 ccs 本身是握手过程中的
			// 只有握手完成后才会有 app data

			if !handshakeComplete || expected {
				log.Printf("readLoop unexpected AppData: handshakeComplete=%v, expectedCCS=%v", handshakeComplete, expected)
				session.in.setErrorLocked(errors.New("alertUnexpectedMessage"))
				c.msgChan <- readMsgItem{err: errors.New("alertUnexpectedMessage")}
				return
			}
			if len(data) == 0 {
				// empty application data record
				// c.msgChan <- readMsgItem{err: errors.New("empty application data record")}
				// 忽略空包，继续读取
				continue
			}
			// 将解密后的data 通过 msgChan 传递给上层
			c.msgChan <- readMsgItem{sessionId: sessionId, remoteId: senderId, msgType: msgType, msg: data, err: nil}

		// 处理 TLS 握手记录
		case recordTypeHandshake:
			if len(data) == 0 {
				c.msgChan <- readMsgItem{err: errors.New("alertUnexpectedMessage")}
				return
			}
			// 发送到 session 专属通道
			select {
			case session.handshakeChan <- sessionMsg{typ: recordTypeHandshake, data: data}:
			default:
				// 防止阻塞 readLoop，虽然理论上握手过程应该在消费
				// log.Println("session handshake channel full, dropping message")
				log.Printf("readLoop handshake channel blocked for session %s", session.id)
				c.msgChan <- readMsgItem{err: errors.New("handshake channel blocked")}
				return
			}

		case recordTypeChangeCipherSpec:
			if len(data) != 1 || data[0] != 1 {
				session.in.setErrorLocked(errors.New("alertDecodeError"))
				c.msgChan <- readMsgItem{err: errors.New("alertDecodeError")}
				return
			}

			// 变更 in 的密码套件
			if err := session.in.changeCipherSpec(); err != nil {
				log.Printf("readLoop changeCipherSpec error: %v", err)
				session.in.setErrorLocked(errors.New("change cipher failed!"))
				c.msgChan <- readMsgItem{err: errors.New("change cipher failed!")}
				return
			}
			// 通知 Session CCS 已收到
			select {
			case session.handshakeChan <- sessionMsg{typ: recordTypeChangeCipherSpec, data: data}:
			default:
				log.Printf("readLoop handshake channel blocked on CCS for session %s", session.id)
				c.msgChan <- readMsgItem{err: errors.New("handshake channel blocked on CCS")}
				return
			}
		}
	}
}

func (c *Conn) WriteMessage(messageType int, message []byte) error {

	// 似乎这里必须要写一段拆包逻辑来获取 receiveId 或者说 remoteId
	// 和服务端的拆包逻辑相同，和模拟客户端的打包逻辑相反
	remoteId, err := parseReceivedMsg(message, c.config.compressor(), c.config.encoder())
	if err != nil {
		return err
	}
	sessionId := getSessionID(c.hostId, remoteId)

	c.sessionsMu.Lock()
	session := c.sessions[sessionId]
	if session == nil {
		// 初始化session
		session = NewSession(sessionId, remoteId, c)
		c.sessions[sessionId] = session
	}
	c.sessionsMu.Unlock()
	// 看起来在 write 这边握手操作是可以前置的，因为他在写操作之前就可以知道是要给谁发
	// 从而获取到对应 session，但是这样的话和某个用户之间的首次通信就会是一个握手数据，而不是应用数据【没有漏一条应用数据进行握手触发的效果】
	// 就会和 read 那边的逻辑对不上，所以还是需要漏一个应用数据的
	// 所以 write 这边的握手触发也要后置，先 write 一条再说

	// 三种数据类型：应用、握手、CCS，这里肯定是应用来的

	// 握手 (必须前置，否则第一条应用数据会导致接收端 readLoop 报错)
	if err := session.Handshake(); err != nil {
		return err
	}

	// Wait for handshake to complete?
	// session.Handshake() blocks until one stage is done, but for full handshake it should wait until ready?
	// The current Handshake() implementation drives the state machine.

	err = c.writeRecordLocked(recordTypeApplicationData, message, session)
	if err != nil {
		return err
	}

	// 握手检查（握手确实要后置，但是session相关，即使是第一条消息，也会带session前缀所以session相关不后置）
	// if err := session.Handshake(); err != nil {
	// 	return err
	// }

	if err := session.out.err; err != nil {
		return err
	}

	if !session.isHandshakeComplete.Load() {
		return errors.New("[Write] handshake not complete")
	}
	return nil
}

// 现在还有必要使用 outBufPool 吗
// 与 readRecord 同理 writeRecord由于被应用层和握手层调用，所以应该是会有并发问题的（又好像没有）
func (c *Conn) writeRecordLocked(typ recordType, data []byte, session *Session) error {
	// writeRecordLocked 写入记录，这里的 type 只能是握手/应用/变更密码
	if len(data) == 0 {
		return errors.New("zero length write")
	}

	// 直接分配内存，避免 sync.Pool 不当使用导致的 panic 风险和代码复杂度
	// 头部格式：[1字节类型][10字节HostID]
	outBuf := make([]byte, 11)
	outBuf[0] = byte(typ)
	copy(outBuf[1:11], c.hostId)

	var err error
	// encrypt 方法通常会将加密后的内容追加到 outBuf 后面
	outBuf, err = session.out.encrypt(outBuf, data, c.config.rand())
	if err != nil {
		return err
	}
	err = c.conn.WriteMessage(websocket.BinaryMessage, outBuf)
	if err != nil {
		return err
	}

	return nil
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) SetReadDeadline(timeout time.Duration) error {
	return c.conn.SetReadDeadline(time.Now().Add(timeout))
}

func (c *Conn) SetWriteDeadline(timeout time.Duration) error {
	return c.conn.SetWriteDeadline(time.Now().Add(timeout))
}

func (c *Conn) SetReadLimit(limit int64) {
	c.conn.SetReadLimit(limit)

}

func (c *Conn) SetPingHandler(handler PingPongHandler) {
	c.conn.SetPingHandler(handler)
}

func (c *Conn) SetPongHandler(handler PingPongHandler) {
	c.conn.SetPongHandler(handler)
}

func (c *Conn) LocalAddr() string {
	return c.conn.LocalAddr().String()
}

// func NewWebSocket(connType int) *Default {
// 	return &Default{ConnType: connType}
// }

func (c *Conn) Dial(urlStr string, requestHeader http.Header) (*http.Response, error) {
	conn, httpResp, err := websocket.DefaultDialer.Dial(urlStr, requestHeader)
	if err == nil {
		c.conn = conn
	}
	return httpResp, err
}

func (c *Conn) IsNil() bool {
	if c.conn != nil {
		return false
	}
	return true
}

// 返回发送者的id和消息内容未解密的 rawContentData 列表，虽然是列表但是就一个数据一般
func parseReceivedMsg(msg []byte, compressor compressor.Compressor, encoder encoder.Encoder) (string, error) {

	// 解压
	decompressMsg, err := compressor.DecompressWithPool(msg)
	if err != nil {
		log.Printf("解压消息失败: %v", err)
		return "", err
	}

	// 解码
	var req Req
	err = encoder.Decode(decompressMsg, &req)
	if err != nil {
		log.Printf("解码消息失败: %v", err)
		return "", err
	}

	var msgData sdkws.MsgData
	if err := proto.Unmarshal(req.Data, &msgData); err != nil {
		return "", err
	}

	// var pushMsg sdkws.PushMessages
	// // 反序列化到 PushMessages 结构体
	// err = proto.Unmarshal(req.Data, &pushMsg)
	// if err != nil {
	// 	log.Printf("反序列化消息失败: %v", err)
	// 	return "", nil, err
	// }

	return msgData.RecvID, nil
}

func getSessionID(A, B string) SessionID {
	if A < B {
		return SessionID(A + "_" + B)
	}
	return SessionID(B + "_" + A)
}
