package openimmarshal

import (
	"github.com/albert/ws_client/compressor"
	"github.com/albert/ws_client/encoder"
	"github.com/openimsdk/protocol/sdkws"
)

type OpenIMParser struct {
	encoder    encoder.Encoder
	compressor compressor.Compressor
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
	//
	Data []byte `json:"data"`
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
	Content string `json:"content"` // 字段名需与JSON的key对应，json tag指定JSON中的键名
}

// 兼容性改造，包一层配上两个获取 ID 的方法
// 使用指针嵌入避免复制 protobuf 内部的 sync.Mutex
type MsgData struct {
	*sdkws.MsgData

	// Write 方向复用结构体
	Req *Req // 保存原始的 Req，以便写回时复用

	// Read 方向复用结构体
	Resp    *Resp               // 保存原始的 Resp，以便写回时复用
	PushMsg *sdkws.PushMessages // 保存原始的 PushMsg，以便写回时复用
}

func (m *MsgData) GetSendID() string {
	return m.SendID
}

func (m *MsgData) GetRecvID() string {
	return m.RecvID
}

func (m *MsgData) GetContent() []byte {
	return m.Content
}

func (m *MsgData) SetContent(content []byte) {
	m.Content = content
}

// type MsgData struct {
// 	state            protoimpl.MessageState `protogen:"open.v1"`
// 	SendID           string                 `protobuf:"bytes,1,opt,name=sendID,proto3" json:"sendID"`
// 	RecvID           string                 `protobuf:"bytes,2,opt,name=recvID,proto3" json:"recvID"`
// 	GroupID          string                 `protobuf:"bytes,3,opt,name=groupID,proto3" json:"groupID"`
// 	ClientMsgID      string                 `protobuf:"bytes,4,opt,name=clientMsgID,proto3" json:"clientMsgID"`
// 	ServerMsgID      string                 `protobuf:"bytes,5,opt,name=serverMsgID,proto3" json:"serverMsgID"`
// 	SenderPlatformID int32                  `protobuf:"varint,6,opt,name=senderPlatformID,proto3" json:"senderPlatformID"`
// 	SenderNickname   string                 `protobuf:"bytes,7,opt,name=senderNickname,proto3" json:"senderNickname"`
// 	SenderFaceURL    string                 `protobuf:"bytes,8,opt,name=senderFaceURL,proto3" json:"senderFaceURL"`
// 	SessionType      int32                  `protobuf:"varint,9,opt,name=sessionType,proto3" json:"sessionType"`
// 	MsgFrom          int32                  `protobuf:"varint,10,opt,name=msgFrom,proto3" json:"msgFrom"`
// 	ContentType      int32                  `protobuf:"varint,11,opt,name=contentType,proto3" json:"contentType"`
// 	Content          []byte                 `protobuf:"bytes,12,opt,name=content,proto3" json:"content"`
// 	Seq              int64                  `protobuf:"varint,14,opt,name=seq,proto3" json:"seq"`
// 	SendTime         int64                  `protobuf:"varint,15,opt,name=sendTime,proto3" json:"sendTime"`
// 	CreateTime       int64                  `protobuf:"varint,16,opt,name=createTime,proto3" json:"createTime"`
// 	Status           int32                  `protobuf:"varint,17,opt,name=status,proto3" json:"status"`
// 	IsRead           bool                   `protobuf:"varint,18,opt,name=isRead,proto3" json:"isRead"`
// 	Options          map[string]bool        `protobuf:"bytes,19,rep,name=options,proto3" json:"options" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"varint,2,opt,name=value"`
// 	OfflinePushInfo  *OfflinePushInfo       `protobuf:"bytes,20,opt,name=offlinePushInfo,proto3" json:"offlinePushInfo"`
// 	AtUserIDList     []string               `protobuf:"bytes,21,rep,name=atUserIDList,proto3" json:"atUserIDList"`
// 	AttachedInfo     string                 `protobuf:"bytes,22,opt,name=attachedInfo,proto3" json:"attachedInfo"`
// 	Ex               string                 `protobuf:"bytes,23,opt,name=ex,proto3" json:"ex"`
// 	unknownFields    protoimpl.UnknownFields
// 	sizeCache        protoimpl.SizeCache
// }

// type OfflinePushInfo struct {
// 	state         protoimpl.MessageState `protogen:"open.v1"`
// 	Title         string                 `protobuf:"bytes,1,opt,name=title,proto3" json:"title"`
// 	Desc          string                 `protobuf:"bytes,2,opt,name=desc,proto3" json:"desc"`
// 	Ex            string                 `protobuf:"bytes,3,opt,name=ex,proto3" json:"ex"`
// 	IOSPushSound  string                 `protobuf:"bytes,4,opt,name=iOSPushSound,proto3" json:"iOSPushSound"`
// 	IOSBadgeCount bool                   `protobuf:"varint,5,opt,name=iOSBadgeCount,proto3" json:"iOSBadgeCount"`
// 	SignalInfo    string                 `protobuf:"bytes,6,opt,name=signalInfo,proto3" json:"signalInfo"`
// 	unknownFields protoimpl.UnknownFields
// 	sizeCache     protoimpl.SizeCache
// }
