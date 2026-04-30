package imparser

import "errors"

var ErrBypassSecureWS = errors.New("bypass secure ws")
var ErrDropSecureWS = errors.New("drop secure ws")

const SecureWSMarker = "__secure_ws__:"

type MsgData interface {
	GetSendID() string
	GetRecvID() string
	GetContent() []byte
	SetContent(content []byte)
	GetEx() string
	SetEx(ex string)
}

type IMParser interface {
	ConstructMsgData(sendID, recvID string, msg []byte) MsgData
	MsgDataToBytesWriteBound(msgData MsgData) ([]byte, error)
	BytesToMsgDataWriteBound(data []byte) (MsgData, error)
	MsgDataToBytesReadBound(msgData MsgData) ([]byte, error)
	BytesToMsgDataReadBound(data []byte) (MsgData, error)
}

type ReadBatchParser interface {
	BytesToMsgDataReadBoundBatch(data []byte) ([]MsgData, error)
}

func ConstructHandshakeMsg(sendID, recvID string, msg []byte, p IMParser) MsgData {
	return p.ConstructMsgData(sendID, recvID, msg)
}

func ConstructCCSMsg(sendID, recvID string, p IMParser) MsgData {
	return p.ConstructMsgData(sendID, recvID, []byte("CCS"))
}

func ConstructAlterMsg(sendID, recvID string, p IMParser) MsgData {
	return p.ConstructMsgData(sendID, recvID, []byte("Alter"))
}
