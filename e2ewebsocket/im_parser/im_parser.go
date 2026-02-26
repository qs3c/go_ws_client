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
	// MsgData -> []byte -> Server
	// MsgData <- []byte <- Server
	MsgDataToServerWriteBound(msgData MsgData) ([]byte, error)
	MsgDataFromServerWriteBound(data []byte) (MsgData, error)

	// 读方向 序列化与反序列化方法
	// Server -> []byte -> MsgData
	// Server <- []byte <- MsgData
	MsgDataToServerReadBound(msgData MsgData) ([]byte, error)
	MsgDataFromServerReadBound(data []byte) (MsgData, error)
}


