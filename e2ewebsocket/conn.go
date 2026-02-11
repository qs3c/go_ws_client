package e2ewebsocket

import (
	"bytes"
	"context"
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

var cmp = compressor.NewGzipCompressor()
var ecd = encoder.NewGobEncoder()

type Conn struct {
	conn     *websocket.Conn
	hostId   string
	config   *Config
	sessions sync.Map
	msgChan  chan readMsgItem

	parseReceivedMsg func([]byte) (string, error)
	writeMu          sync.Mutex
}

func NewSecureConn(wsconn *websocket.Conn, hostId string, config *Config) (*Conn, error) {
	c := &Conn{
		conn:    wsconn,
		hostId:  hostId,
		config:  config,
		msgChan: make(chan readMsgItem, 128),
	}
	go c.readLoop()
	return c, nil
}

type readMsgItem struct {
	sessionId SessionID
	// ######## remoteId 可能没用
	remoteId string
	// 基础消息
	msgType int
	msg     []byte
	err     error
}

func (c *Conn) readLoop() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("readLoop panic: %v", r)
		}
		// 关闭所有 session 的握手消息通道
		c.sessions.Range(func(key, value any) bool {
			session := value.(*Session)
			session.Close()
			return true
		})
		// 关闭 conn 的应用消息通道
		close(c.msgChan)
		c.Close()
		log.Println("readLoop exited")
	}()

	for {
		if err := c.readRecord(); err != nil {
			return
		}
	}

}

func (c *Conn) readRecord() error {
	msgType, msg, err := c.conn.ReadMessage()
	if err != nil {
		log.Printf("readLoop ReadMessage error: %v", err)
		c.msgChan <- readMsgItem{err: err}
		return err
	}

	// 如果不是二进制类型的，正常传递给上层
	if msgType != websocket.BinaryMessage {
		c.msgChan <- readMsgItem{msgType: msgType, msg: msg}
		return nil
	}

	// 解析 msg 构造 sessionId 并获取到对应的 session
	typ := recordType(msg[0])
	senderId := string(bytes.TrimRight(msg[1:11], "\x00"))
	sessionId := getSessionID(c.hostId, senderId)

	actual, loaded := c.sessions.LoadOrStore(sessionId, NewSession(sessionId, senderId, c))
	session := actual.(*Session)
	if !loaded {
		go func(s *Session) {
			if err := s.Handshake(); err != nil {
				log.Printf("Passive handshake failed for session %s: %v", s.id, err)
			}
		}(session)
	}

	handshakeComplete := session.isHandshakeComplete.Load()

	// 解密
	data, err := session.in.decrypt(msg[11:])
	if err != nil {
		log.Printf("readLoop decrypt error: %v", err)
		// 这个是否合适，一次和 A 之间的解密失败，你和 A 似乎就永别了
		// ====================【设置永久错误和触发session自愈之间有gap，是否应该立即触发自愈而不是设置错误呢？】
		c.terminateSession(session, err)
		// c.msgChan <- readMsgItem{err: err}
		return nil
	}

	switch typ {
	default:
		// 收到来自A的诡异消息，可能被攻击了，终止 session
		log.Printf("readLoop unexpected message type: %d", typ)
		c.terminateSession(session, errors.New("UnexpectedMessage"))
		return nil
	// 收到来自 A 的 session 销毁通知
	case recordTypeAlert:
		if len(data) < 2 {
			log.Printf("收到不合法的Alert消息，长度小于2")
			c.terminateSession(session, errors.New("AlertMessageLenError"))
			return nil
		}
		log.Printf("readLoop received alert: level=%d, desc=%d from %s", data[0], data[1], senderId)
		// 收到 Alert，直接销毁本地 Session
		c.terminateSession(session, errors.New("received alert"))
		return nil
	// 收到来自 A 的应用数据记录
	case recordTypeApplicationData:
		// #############handshake 是异步的 这里的话很有可能没完成啊！
		// 特殊情况：握手太慢，第二条来的有太快了，来了还没握好，怎么办，直接永久错误？

		if !handshakeComplete && loaded {
			// 特殊情况：握手其实已经完成了（Handshake函数返回了），但是状态位 isHandshakeComplete 还没来得及设置
			// 此时应用数据就已经到了。我们需要给一点时间让握手协程更新状态。
			// 这是一个非常短的竞态窗口。
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			if !session.isHandshakeComplete.Load() {
				log.Printf("readLoop waiting for handshake completion for session %s...", sessionId)
				select {
				case <-session.handshakeComplete:
				case <-ctx.Done():
					log.Printf("readLoop handshake wait timeout for session %s", sessionId)
					c.terminateSession(session, errors.New("alertUnexpectedMessage"))
					return nil
				case <-session.done:
					return nil // Session closed
				}
			}
		}
		// 正常向上层传递应用数据记录
		c.msgChan <- readMsgItem{sessionId: sessionId, remoteId: senderId, msgType: msgType, msg: data, err: nil}

	// 收到来自 A 的握手记录
	case recordTypeHandshake:

		// 发送到 session 专属通道
		select {
		case session.handshakeChan <- sessionMsg{typ: recordTypeHandshake, data: data}:
		default:
			// default 分支防止阻塞 readLoop 而存在，虽然理论上握手过程应该在消费不会阻塞
			// 正常来说不可能阻塞，如果握手消息通道都塞满了说明 session 一定是出问题了
			log.Printf("readLoop handshake channel blocked for session %s", session.id)
			c.terminateSession(session, errors.New("handshake channel blocked"))
			return nil
		}

	case recordTypeChangeCipherSpec:
		// CCS 消息检查
		if len(data) != 1 || data[0] != 1 {
			c.terminateSession(session, errors.New("alertDecodeError"))
			return nil
		}

		// 变更 in 的密码套件
		if err := session.in.changeCipherSpec(); err != nil {
			log.Printf("readLoop changeCipherSpec error: %v", err)
			c.terminateSession(session, errors.New("change cipher failed!"))
			return nil
		}
	}
	return nil
}

func (c *Conn) ReadMessage() (int, []byte, error) {
	item, ok := <-c.msgChan
	if !ok {
		return 0, nil, errors.New("connection closed")
	}
	return item.msgType, item.msg, item.err
}

func (c *Conn) WriteMessage(messageType int, message []byte) error {

	// 似乎这里必须要写一段拆包逻辑来获取 receiveId 或者说 remoteId
	// 和服务端的拆包逻辑相同，和模拟客户端的打包逻辑相反
	var remoteId string
	var err error
	if c.parseReceivedMsg == nil {
		remoteId, err = parseReceivedMsgOPENIM(message)
		if err != nil {
			return err
		}
	} else {
		remoteId, err = c.parseReceivedMsg(message)
		if err != nil {
			return err
		}
	}

	sessionId := getSessionID(c.hostId, remoteId)

	var session *Session
	if val, ok := c.sessions.Load(sessionId); ok {
		session = val.(*Session)
	}

	// ##################惰性重建：如果 session 存在但已损坏，销毁并重建，这个不是很惰性其实
	// if session != nil && session.Err() != nil {
	// 	log.Printf("Session %s is broken (err: %v), discarding and creating new one", sessionId, session.Err())
	// 	c.terminateSession(session, session.Err())
	// 	session = nil
	// }

	if session == nil {
		// 初始化session
		session = NewSession(sessionId, remoteId, c)
		actual, _ := c.sessions.LoadOrStore(sessionId, session)
		session = actual.(*Session)
	}

	// 握手
	// 似乎不需要后置握手了
	if err := session.Handshake(); err != nil {
		c.terminateSession(session, err)
		return err
	}

	if !session.isHandshakeComplete.Load() {
		return errors.New("[Write] handshake not complete")
	}

	err = c.writeRecordLocked(recordTypeApplicationData, message, session)
	if err != nil {
		// 这里要么是加密错（与session有关）要么是ws错（与session无关）
		// 加密错需要 terminateSession 在内部处理了
		return c.Close()
	}
	return nil
}

func (c *Conn) writeRecordLocked(typ recordType, data []byte, session *Session) error {
	if len(data) == 0 {
		return errors.New("zero length write")
	}

	// 构造头部
	// ################# 这里太 openim 了，后面看看怎么弄
	outBuf := make([]byte, 11)
	outBuf[0] = byte(typ)
	copy(outBuf[1:11], c.hostId)

	// 加密
	var err error
	outBuf, err = session.out.encrypt(outBuf, data, c.config.rand())
	if err != nil {
		c.terminateSession(session, err)
		return nil
	}

	// 发送
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
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

func parseReceivedMsgOPENIM(msg []byte) (string, error) {

	// 解压
	decompressMsg, err := cmp.DecompressWithPool(msg)
	if err != nil {
		log.Printf("解压消息失败: %v", err)
		return "", err
	}

	// 解码
	var req Req
	err = ecd.Decode(decompressMsg, &req)
	if err != nil {
		log.Printf("解码消息失败: %v", err)
		return "", err
	}

	// 反序列化
	var msgData sdkws.MsgData
	if err := proto.Unmarshal(req.Data, &msgData); err != nil {
		return "", err
	}

	return msgData.RecvID, nil
}

func getSessionID(A, B string) SessionID {
	if A < B {
		return SessionID(A + "_" + B)
	}
	return SessionID(B + "_" + A)
}

// 终止session
func (c *Conn) terminateSession(session *Session, reason error) error {
	if session == nil {
		return reason
	}

	// 0. Try to notify peer (Best Effort)
	// AlertLevel: 2 (Fatal), AlertDescription: 80 (Internal Error)
	// 即使发送失败也不影响后续重建
	// 注意防止递归：writeRecordLocked 内部如果出错不要再调 terminateSession
	// 所以这里如果 session 已经坏了，writeRecordLocked 可能会失败并返回错误，
	// 但是 terminateSession 只管 close，不管 writeRecordLocked 的死活
	// 实际上 writeRecordLocked 需要 session，如果 session 被 close 了，encryption 可能会失败
	// 但此时还没 close，所以尝试发送
	_ = c.writeRecordLocked(recordTypeAlert, []byte{2, 80}, session)

	// 2. 清理资源 (Close channels, wake up blocked goroutines)
	session.Close() // SetError calls Close

	// 3. 从映射表移除 (Remove from map)
	c.sessions.Delete(session.id)

	log.Printf("Session %s terminated: %v", session.id, reason)
	return reason
}

// 重建session，自愈逻辑
// func (c *Conn) rebuildSession(oldSession *Session, reason error) *Session {
// 	log.Printf("Session %s broken (%v), rebuilding...", oldSession.id, reason)

// 	// 0. Try to notify peer (Best Effort)
// 	// AlertLevel: 2 (Fatal), AlertDescription: 80 (Internal Error)
// 	// 即使发送失败也不影响后续重建
// 	_ = c.writeRecordLocked(recordTypeAlert, []byte{2, 80}, oldSession)

// 	// 1. Terminate old session
// 	c.terminateSession(oldSession, reason)

// 	// 2. Create new session
// 	newSession := NewSession(oldSession.id, oldSession.remoteId, c)
// 	c.sessions.Store(newSession.id, newSession)

// 	// 3. Handshake (Async)
// 	go func() {
// 		log.Printf("Starting handshake for new session %s", newSession.id)
// 		if err := newSession.Handshake(); err != nil {
// 			log.Printf("New session handshake failed: %v", err)
// 			c.terminateSession(newSession, err)
// 		} else {
// 			log.Printf("New session handshake success: %s", newSession.id)
// 		}
// 	}()

//		return newSession
//	}
type PingPongHandler func(string) error
