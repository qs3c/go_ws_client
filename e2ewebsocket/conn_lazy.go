//go:build ignore
package e2ewebsocket

import (
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

	// sessions map[SessionID]*Session
	sessions sync.Map

	readQueue []readMsgItem
}

func NewSecureConn(wsconn *websocket.Conn, hostId string, config *Config) *Conn {
	return &Conn{
		conn:     wsconn,
		hostId:   hostId,
		// sessions: make(map[SessionID]*Session),
		config:   config,
	}
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
	// 1. 优先从队列读取【其实这里总的来说都是二进制应用消息了，少有其他类型的消息，比如Close消息】
	for len(c.readQueue) == 0 {
		if err := c.readRecord(); err != nil {
			return 0, nil, err
		}
		// 处理二次握手消息相关的逻辑要放到别的地方检查，不在这里了
		// for c.hand.Len() > 0 {
		// 	if err := c.handlePostHandshakeMessage(); err != nil {
		// 		return 0,nil, err
		// 	}
		// }
	}

	item := c.readQueue[0]
	c.readQueue = c.readQueue[1:]

	if item.sessionId == "" {
		// 说明不是二进制应用消息，直接返回给上层处理即可
		return item.msgType, item.msg, item.err
	}

	// 是二进制应用消息，那么就拿出对应的session，可能存在第一次通信的情况，session并不存在
	session := c.sessions[item.sessionId]
	if session == nil {
		// 到这里的时候 session 不可能为 nil 了
		// 如果是 nil 那么是有问题的
		return 0, nil, errors.New("session not found")
	}
	if err := session.Handshake(); err != nil {
		log.Printf("session handshake failed: %v", err)
	}
	return item.msgType, item.msg, item.err

}

func (c *Conn) readRecord() error {
	return c.readRecordOrCCS(false)
}

// 关于 CCS 的读写归属是不同的，比较特殊的，读归conn，写归session
func (c *Conn) readChangeCipherSpec() error {
	return c.readRecordOrCCS(true)
}

func (c *Conn) readRecordOrCCS(expectChangeCipherSpec bool) error {

	// 这个函数主要处理消息分发
	// 进来先读一条数据再做打算
	msgType, msg, err := c.conn.ReadMessage()
	if err != nil {
		return err
	}
	// 如果不是二进制类型的，正常传递给上层
	if msgType != websocket.BinaryMessage {
		c.readQueue = append(c.readQueue, readMsgItem{sessionId: "", remoteId: "", msgType: msgType, msg: msg, err: err})
		return nil
	}
	// 如果是二进制类型的消息，那么要解析出记录类型、用户id等信息
	// 找到对应的 session 然后再进行握手状态相关的校验

	// 解析 msg
	typ := recordType(msg[0])
	senderId := string(msg[1:11])

	// senderId, rawContentDatas, err := parseReceivedMsg(msg, c.config.Compressor, c.config.Encoder)
	// if err != nil {
	// 	return err
	// }

	// 构造sessionId 并获取到对应的session
	sessionId := getSessionID(c.hostId, senderId)
	session := c.sessions[sessionId]
	if session == nil {
		// session 创建逻辑应该在这里
		session = NewSession(sessionId, senderId, c)
		c.sessions[sessionId] = session
	}
	// 握手状态相关的校验，全部后置
	if session.in.err != nil {
		return session.in.err
	}

	handshakeComplete := session.isHandshakeComplete.Load()

	// 校验结束，开始解密
	data, err := session.in.decrypt(msg[11:])
	if err != nil {
		return session.in.setErrorLocked(errors.New("decrypt failed"))
	}

	// 如果是 Application Data 消息，且没有加密算法
	// 则发送 alertUnexpectedMessage 警告
	// Application Data messages are always protected.

	// 因为现在是允许跑空一条应用数据的，所以不能有这个检查！【todo：换成别的检查】
	//【session中增加一个字段，初始化为false，握手函数中会被置为true，
	// 也就是说这里如果是刚初始化的session，那么这个字段就是false，
	// 那么就说明是第一次通信，那么就允许跑空一条应用数据】
	// if session.in.cipher == nil && typ == recordTypeApplicationData {
	// 	return session.in.setErrorLocked(errors.New("alertUnexpectedMessage"))
	// }

	// 处理不同类型的TLS记录
	switch typ {
	default:
		return session.in.setErrorLocked(errors.New("alertUnexpectedMessage"))

	// 处理 TLS 应用数据记录
	case recordTypeApplicationData:
		if !handshakeComplete || expectChangeCipherSpec {
			return session.in.setErrorLocked(errors.New("alertUnexpectedMessage"))
		}
		if len(data) == 0 {
			// todo：retryReadRecord
			// return c.retryReadRecord(expectChangeCipherSpec)
			return errors.New("empty application data record")
		}
		// 将解密后的data 通过 readQueue 传递给上层
		c.readQueue = append(c.readQueue, readMsgItem{sessionId: sessionId, remoteId: senderId, msgType: msgType, msg: data, err: err})
		return nil

	// 处理 TLS 握手记录
	case recordTypeHandshake:
		if len(data) == 0 || expectChangeCipherSpec {
			return errors.New("alertUnexpectedMessage")
		}
		session.hand = append(session.hand, data)

	case recordTypeChangeCipherSpec:
		// todo : 扩展为可携带 sm2 的 cs 数据【感觉可以通过hand传递过去，然后在readFinished中处理】
		if len(data) != 1 || data[0] != 1 {
			return session.in.setErrorLocked(errors.New("alertDecodeError"))
		}
		// Handshake messages are not allowed to fragment across the CCS.
		if len(session.hand) > 0 {
			return session.in.setErrorLocked(errors.New("alertUnexpectedMessage"))
		}
		if !expectChangeCipherSpec {
			return session.in.setErrorLocked(errors.New("alertUnexpectedMessage"))
		}
		// 变更 in 的密码套件
		if err := session.in.changeCipherSpec(); err != nil {
			return session.in.setErrorLocked(errors.New("change cipher failed!"))
		}

	}

	return nil
}

func (c *Conn) WriteMessage(messageType int, message []byte) error {

	// 似乎这里必须要写一段拆包逻辑来获取 receiveId 或者说 remoteId
	// 和服务端的拆包逻辑相同，和模拟客户端的打包逻辑相反
	remoteId, err := parseReceivedMsg(message, c.config.compressor(), c.config.encoder())
	if err != nil {
		return err
	}
	sessionId := getSessionID(c.hostId, remoteId)

	session := c.sessions[sessionId]
	if session == nil {
		// 初始化session
		session = NewSession(sessionId, remoteId, c)
		c.sessions[sessionId] = session
	}
	// 看起来在 write 这边握手操作是可以前置的，因为他在写操作之前就可以知道是要给谁发
	// 从而获取到对应 session，但是这样的话和某个用户之间的首次通信就会是一个握手数据，而不是应用数据【没有漏一条应用数据进行握手触发的效果】
	// 就会和 read 那边的逻辑对不上，所以还是需要漏一个应用数据的
	// 所以 write 这边的握手触发也要后置，先 write 一条再说

	// 三种数据类型：应用、握手、CCS，这里肯定是应用来的

	err = c.writeRecordLocked(recordTypeApplicationData, message, session)
	if err != nil {
		return err
	}

	// 握手检查（握手确实要后置，但是session相关，即使是第一条消息，也会带session前缀所以session相关不后置）
	if err := session.Handshake(); err != nil {
		return err
	}

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
