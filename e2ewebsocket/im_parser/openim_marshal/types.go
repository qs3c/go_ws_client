package openimmarshal

import (
	"sync"

	"github.com/openimsdk/protocol/sdkws"
	"github.com/qs3c/e2e-secure-ws/compressor"
	"github.com/qs3c/e2e-secure-ws/encoder"
)

type OpenIMParser struct {
	encoder        encoder.Encoder
	compressor     compressor.Compressor
	realtimeMsgMap sync.Map
}

func NewOpenIMParser(encoder encoder.Encoder, compressor compressor.Compressor) *OpenIMParser {
	return &OpenIMParser{
		encoder:    encoder,
		compressor: compressor,
	}
}

type Req struct {
	ReqIdentifier int32  `json:"reqIdentifier" validate:"required"`
	Token         string `json:"token"`
	SendID        string `json:"sendID"        validate:"required"`
	OperationID   string `json:"operationID"   validate:"required"`
	MsgIncr       string `json:"msgIncr"       validate:"required"`
	Data          []byte `json:"data"`
}

type Resp struct {
	ReqIdentifier int32  `json:"reqIdentifier"`
	MsgIncr       string `json:"msgIncr"`
	OperationID   string `json:"operationID"`
	ErrCode       int    `json:"errCode"`
	ErrMsg        string `json:"errMsg"`
	Data          []byte `json:"data"`
}

type Message struct {
	Content string `json:"content"`
}

type MsgData struct {
	*sdkws.MsgData
	Req        *Req
	Resp       *Resp
	PushMsg    *sdkws.PushMessages
	SecureRead bool
}

func (m *MsgData) GetSendID() string {
	if m == nil || m.MsgData == nil {
		return ""
	}
	return m.SendID
}

func (m *MsgData) GetRecvID() string {
	if m == nil || m.MsgData == nil {
		return ""
	}
	return m.RecvID
}

func (m *MsgData) GetContent() []byte {
	if m == nil || m.MsgData == nil {
		return nil
	}
	return m.Content
}

func (m *MsgData) SetContent(content []byte) {
	if m == nil || m.MsgData == nil {
		return
	}
	m.Content = content
}

func (m *MsgData) GetEx() string {
	if m == nil || m.MsgData == nil {
		return ""
	}
	return m.Ex
}

func (m *MsgData) SetEx(ex string) {
	if m == nil || m.MsgData == nil {
		return
	}
	m.Ex = ex
}

func (m *MsgData) IsSecureReadBound() bool {
	return m != nil && m.SecureRead
}

func (m *MsgData) ReadReqIdentifier() int32 {
	if m == nil || m.Resp == nil {
		return 0
	}
	return m.Resp.ReqIdentifier
}
