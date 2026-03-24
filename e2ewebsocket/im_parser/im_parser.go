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
	MsgDataToServerWriteBound(msgData MsgData) ([]byte, error)
	MsgDataFromServerWriteBound(data []byte) (MsgData, error)

	// 读方向 序列化与反序列化方法
	// Server -> []byte -> MsgData	【之前client已有】
	// Server <- []byte <- MsgData	【本次需补充的方向，与服务器组织消息发送给客户端的逻辑相同】
	MsgDataToServerReadBound(msgData MsgData) ([]byte, error)
	MsgDataFromServerReadBound(data []byte) (MsgData, error)
}


