package e2ewebsocket

import (
	"errors"
	"log"

	"github.com/albert/ws_client/compressor"
	"github.com/albert/ws_client/encoder"
	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
)

type Conn struct {
	conn websocket.Conn

	hostId string

	sessions map[string]*Session

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
	readQueue []readMsgItem

	config *Config
}

type readMsgItem struct {
	msgType int
	msg     []byte
	err     error
}

func (c *Conn) ReadMessage() (int, []byte, error) {
	// 1. 优先从队列读取
	if len(c.readQueue) > 0 {
		item := c.readQueue[0]
		// 移除头部元素 (切片操作)
		c.readQueue = c.readQueue[1:]
		// 如果因为底层数组太大而在意内存泄漏，可以在这里根据情况重建 slice，
		// 但通常对于这种小队列没必要。
		return item.msgType, item.msg, item.err
	}

	// 2. 队列为空，从底层连接读取
	msgType, msg, err := c.conn.ReadMessage()
	// 除了二进制消息，其他都正常返回
	if msgType != websocket.BinaryMessage {
		return msgType, msg, err
	}

	// 3. 这里是演示逻辑：假设某种情况下我们需要把读出来的消息放回队列
	// 实际使用时，调用者会在外部判断，如果“读多了”或者“读到了握手包”，
	// 会调用类似 unread / pushBack 的方法。
	// 但既然 ReadMessage 接口定义如此，这里直接返回即可。
	// 只有当有【握手逻辑】介入，且握手逻辑多读了数据时，才需要写入这个队列。

	return msgType, msg, err
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
		c.readQueue = append(c.readQueue, readMsgItem{msgType: msgType, msg: msg, err: err})
		return nil
	}
	// 如果是二进制类型的消息，那么要解析出记录类型、用户id等信息
	// 找到对应的 session 然后再进行握手状态相关的校验

	// 解析 msg
	typ := recordType(msg[0])
	senderId, rawContentDatas, err := parseReceivedMsg(msg, c.config.Compressor, c.config.Encoder)
	if err != nil {
		return err
	}

	// 构造sessionId 并获取到对应的session
	sessionId := getSessionID(c.hostId, senderId)
	session := c.sessions[sessionId]
	if session == nil {
		return errors.New("session not found")
	}
	// 握手状态相关的校验，全部后置
	if session.in.err != nil {
		return session.in.err
	}

	handshakeComplete := session.isHandshakeComplete.Load()

	// 校验结束，开始解密
	data, err := session.in.decrypt(rawContentDatas[0])
	if err != nil {
		return session.in.setErrorLocked(errors.New("decrypt failed"))
	}

	// 如果是 Application Data 消息，且没有加密算法
	// 则发送 alertUnexpectedMessage 警告
	// Application Data messages are always protected.
	if session.in.cipher == nil && typ == recordTypeApplicationData {
		return session.in.setErrorLocked(errors.New("alertUnexpectedMessage"))
	}


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
		c.readQueue = append(c.readQueue, readMsgItem{msgType: msgType, msg: data, err: err})
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
		// In TLS 1.3, change_cipher_spec records are ignored until the
		// Finished. See RFC 8446, Appendix D.4. Note that according to Section
		// 5, a server can send a ChangeCipherSpec before its ServerHello, when
		// c.vers is still unset. That's not useful though and suspicious if the
		// server then selects a lower protocol version, so don't allow that.
		// if c.vers == VersionTLS13 {
		// 	return c.retryReadRecord(expectChangeCipherSpec)
		// }
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

// 返回发送者的id和消息内容未解密的 rawContentData 列表，虽然是列表但是就一个数据一般
func parseReceivedMsg(msg []byte, compressor compressor.Compressor, encoder encoder.Encoder) (string, [][]byte, error) {

	// 解压
	decompressMsg, err := compressor.DecompressWithPool(msg)
	if err != nil {
		log.Printf("解压消息失败: %v", err)
		return "", nil, err
	}

	// 解码
	var resp Resp
	err = encoder.Decode(decompressMsg, &resp)
	if err != nil {
		log.Printf("解码消息失败: %v", err)
		return "", nil, err
	}

	var pushMsg sdkws.PushMessages
	// 反序列化到 PushMessages 结构体
	err = proto.Unmarshal(resp.Data, &pushMsg)
	if err != nil {
		log.Printf("反序列化消息失败: %v", err)
		return "", nil, err
	}

	senderIds := make([]string, 0, 1)
	// var senderIds string
	rawContentList := make([][]byte, 0, 1)

	msgMap := pushMsg.Msgs
	// 虽然是循环，但是单聊的时候 map 里只会有一个会话
	for _, pullMsg := range msgMap {
		// 一个会话里可能有多个消息，但单聊的时候一般只有一个
		for _, msgData := range pullMsg.Msgs {

			// log.Printf("From会话[%s]收到消息: %s", conversationId, recvMsg.Content)
			senderIds = append(senderIds, msgData.SendID)
			rawContentList = append(rawContentList, msgData.Content)
		}
	}
	return senderIds[0], rawContentList, nil
}

func getSessionID(A, B string) string {
	if A < B {
		return A + "_" + B
	}
	return B + "_" + A
}
