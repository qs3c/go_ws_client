package e2ewebsocket

import (
	"bytes"
	"errors"
	"log"
	"sync"

	"github.com/gorilla/websocket"
)

var cmp = compressor.NewGzipCompressor()
var ecd = encoder.NewGobEncoder()

type Conn struct {
	conn *websocket.Conn
	hostId string
	config *Config
	sessions sync.Map
	msgChan chan readMsgItem

	parseReceivedMsg func([]byte) (string, error)
	writeMu sync.Mutex
}

func NewSecureConn(wsconn *websocket.Conn hostId string, config *Config) (*Conn, error) {
	c := &Conn{
		conn: wsconn,
		hostId: hostId,
		config: config,
		msgChan: make(chan readMsgItem, 128),
	}	
	go c.readLoop()
	return c, nil
}



type readMsgItem struct{
	sessionId SessionID
	// ######## remoteId 可能没用
	remoteId  string
	// 基础消息
	msgType   int
	msg       []byte
	err       error
}

func (c *Conn) readLoop() {
	defer func(){
		if r:=recover();r!=nil{
		log.Printf("readLoop panic: %v", r)
		}
		// 关闭所有 session 的握手消息通道
		c.sessions.Range(func(key, value any) bool {
			session := value.(*Session)
			close(session.handshakeChan)
			return true
		})
		// 关闭 conn 的应用消息通道
		close(c.msgChan)
		log.Println("readLoop exited")
	}()

	for {
		c.readRecord()
	}
	
}

func (c *Conn) readRecord(){
	msgType, msg, err := c.conn.ReadMessage()
	if err != nil {
		log.Printf("readLoop ReadMessage error: %v", err)
		c.msgChan <- readMsgItem{err: err}
		// 这里要return 还是 continue
		return
	}
	
	// 如果不是二进制类型的，正常传递给上层
	if msgType != websocket.BinaryMessage {
		c.msgChan <- readMsgItem{msgType: msgType, msg: msg}
		return
	}

	// 解析 msg 构造 sessionId 并获取到对应的 session
	typ := recordType(msg[0])
	senderId := string(bytes.TrimRight(msg[1:11], "\x00"))
	sessionId := getSessionID(c.hostId, senderId)

	actual, loaded := c.sessions.LoadOrStore(sessionId, NewSession(sessionId, senderId, c))
	session := actual.(*Session)
	if !loaded {
		// 被动创建的 Session，需要主动触发握手以响应对端（对称握手）
		// ########同步握手会阻塞用于泵数据的 readRecord 函数啊所以这里必须异步
		go func(s *Session) {
			if err := s.Handshake(); err != nil {
				log.Printf("Passive handshake failed for session %s: %v", s.id, err)
			}
		}(session)
	}

	// 握手状态校验
	if session.in.err != nil {
		log.Printf("readLoop session error: %v", session.in.err)
		// c.msgChan <- readMsgItem{err: session.in.err}
		return
	}

	handshakeComplete := session.isHandshakeComplete.Load()

	// 解密
	data, err := session.in.decrypt(msg[11:])
	if err != nil {
		log.Printf("readLoop decrypt error: %v", err)
		// 这个是否合适，一次和 A 之间的解密失败，你和 A 似乎就永别了
		session.in.setErrorLocked(errors.New("decrypt failed"))
		// c.msgChan <- readMsgItem{err: err}
		return
	}

    switch typ {
	default:
		// 收到来自A的诡异消息，可能是被攻击了，也是永久关闭和A的通信了
		log.Printf("readLoop unexpected message type: %d", typ)
		session.in.setErrorLocked(errors.New("alertUnexpectedMessage"))
		// c.msgChan <- readMsgItem{err: errors.New("alertUnexpectedMessage")}
		return
	// 收到来自 A 的 session 销毁通知
	case recordTypeAlert:
		if len(data) < 2 {
			// c.msgChan <- readMsgItem{err: errors.New("alert message too short")}
			log.Printf("收到不合法的Alert消息，长度小于2")
			return
		}
		log.Printf("readLoop received alert: level=%d, desc=%d from %s", data[0], data[1], senderId)
		// 收到 Alert，直接销毁本地 Session
		c.sessions.Delete(sessionId)
		return
	// 收到来自 A 的应用数据记录
	case recordTypeApplicationData:
		// #############handshake 是异步的 这里的话很有可能没完成啊！
		// 如果是加载出来的旧 session，没有完成就不行
		// 如果是新 session 也就是第一条和A通信的应用消息，那么没有完成握手也是合法的！
		// 特殊情况：握手太慢，第二条来的有太快了，来了还没握好，怎么办，直接永久错误？
		if !handshakeComplete && loaded {
			log.Printf("readLoop unexpected AppData: handshakeComplete=%v, expectedCCS=%v", handshakeComplete, expected)
			session.in.setErrorLocked(errors.New("alertUnexpectedMessage"))
			// c.msgChan <- readMsgItem{err: errors.New("alertUnexpectedMessage")}
			return
		}
		// 当前场景下，其实收到一个只有自定义添加的头部而body是空包的情况
		// 可以说是不可能的，这相当于上层WriteMessage就是写的空[]byte
		// if len(data) == 0 {
		// 	// empty application data record
		// 	// c.msgChan <- readMsgItem{err: errors.New("empty application data record")}
		// 	// 忽略空包，继续读取
		// 	return
		// }

		// 正常向上层传递应用数据记录
		c.msgChan <- readMsgItem{sessionId: sessionId, remoteId: senderId, msgType: msgType, msg: data, err: nil}

	// 收到来自 A 的握手记录
	case recordTypeHandshake:
		// if len(data) == 0 {
		// 	c.msgChan <- readMsgItem{err: errors.New("alertUnexpectedMessage")}
		// 	return
		// }

		// 发送到 session 专属通道
		select {
		case session.handshakeChan <- sessionMsg{typ: recordTypeHandshake, data: data}:
		default:
			// 防止阻塞 readLoop，虽然理论上握手过程应该在消费不会阻塞
			//########### 但是如果 handshakeChan 写不进去阻塞了，这条握手消息相当于就丢弃掉了
			// log.Println("session handshake channel full, dropping message")
			log.Printf("readLoop handshake channel blocked for session %s", session.id)
			// c.msgChan <- readMsgItem{err: errors.New("handshake channel blocked")}
			return
		}

	case recordTypeChangeCipherSpec:
		// CCS 消息检查
		if len(data) != 1 || data[0] != 1 {
			session.in.setErrorLocked(errors.New("alertDecodeError"))
			// c.msgChan <- readMsgItem{err: errors.New("alertDecodeError")}
			return
		}

		// 变更 in 的密码套件
		if err := session.in.changeCipherSpec(); err != nil {
			log.Printf("readLoop changeCipherSpec error: %v", err)
			session.in.setErrorLocked(errors.New("change cipher failed!"))
			// c.msgChan <- readMsgItem{err: errors.New("change cipher failed!")}
			return
		}
	}

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
		remoteId, err = c.parseReceivedMsgOPENIM(message)
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
	if session != nil && session.out.err != nil {
		log.Printf("Session %s is broken (err: %v), discarding and creating new one", sessionId, session.out.err)
		c.sessions.Delete(sessionId)
		session = nil
	}

	if session == nil {
		// 初始化session
		session = NewSession(sessionId, remoteId, c)
		actual, _ := c.sessions.LoadOrStore(sessionId, session)
		session = actual.(*Session)
	}

	// 握手
	// 似乎不需要后置握手了
	if err := session.Handshake(); err != nil {
		return err
	}

	// 握手检查
	if err := session.out.err; err != nil {
		return err
	}

	if !session.isHandshakeComplete.Load() {
		return errors.New("[Write] handshake not complete")
	}

	err = c.writeRecordLocked(recordTypeApplicationData, message, session)
	if err != nil {
		return err
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
		return err
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