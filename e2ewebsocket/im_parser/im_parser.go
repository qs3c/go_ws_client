package imparser

type MsgData interface{
	GetSendID() string
	GetRecvID() string
	GetContent() []byte
	SetContent(content []byte)
}

type IMParser interface {
	// MsgData 构造方法
	ConstructMsgData(sendID, recvID string, msg []byte) MsgData

	// 写方向 序列化与反序列化方法 
	// MsgData -> []byte -> Server 【之前client已有】
	// MsgData <- []byte <- Server	【本次需补充的方向，与服务器收到客户端消息后的解析逻辑相同】
	MsgDataToBytesWriteBound(msgData MsgData) ([]byte, error)
	BytesToMsgDataWriteBound(data []byte) (MsgData, error)

	// 读方向 序列化与反序列化方法
	// Server -> []byte -> MsgData	【之前client已有】
	// Server <- []byte <- MsgData	【本次需补充的方向，与服务器组织消息发送给客户端的逻辑相同】
	MsgDataToBytesReadBound(msgData MsgData) ([]byte, error)
	BytesToMsgDataReadBound(data []byte) (MsgData, error)
}

// 1 握手消息
func ConstructHandshakeMsg(sendID, recvID string, msg []byte, p IMParser) MsgData {
	return p.ConstructMsgData(sendID, recvID, msg)
}

// 2. CCS 消息
func ConstructCCSMsg(sendID, recvID string, p IMParser) MsgData {
	return p.ConstructMsgData(sendID, recvID, []byte("CCS"))
}

// 3. Alter 消息
func ConstructAlterMsg(sendID, recvID string, p IMParser) MsgData {
	return p.ConstructMsgData(sendID, recvID, []byte("Alter"))
}

