package openimmarshal

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/openimsdk/protocol/sdkws"
	imparser "github.com/qs3c/e2e-secure-ws/e2ewebsocket/im_parser"
	"google.golang.org/protobuf/proto"
)

const realtimePushReqIdentifier int32 = 2001

func (p *OpenIMParser) BytesToMsgDataReadBound(data []byte) (imparser.MsgData, error) {
	items, err := p.BytesToMsgDataReadBoundBatch(data)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, errors.New("secure push message not found")
	}
	for _, item := range items {
		if secureItem, ok := item.(*MsgData); ok && secureItem.SecureRead {
			return item, nil
		}
	}
	return items[0], nil
}

func (p *OpenIMParser) BytesToMsgDataReadBoundBatch(data []byte) ([]imparser.MsgData, error) {
	resp, err := p.decodeAndDecompressReadBound(data)
	if err != nil {
		log.Printf("decode inbound response failed: %v", err)
		return nil, err
	}

	var pushMsg sdkws.PushMessages
	if err := proto.Unmarshal(resp.Data, &pushMsg); err != nil {
		if isSecureInternalResp(resp) {
			return nil, imparser.ErrDropSecureWS
		}
		return nil, imparser.ErrBypassSecureWS
	}
	if len(pushMsg.Msgs) == 0 {
		if isSecureInternalResp(resp) {
			return nil, imparser.ErrDropSecureWS
		}
		return nil, imparser.ErrBypassSecureWS
	}

	if resp.ReqIdentifier != realtimePushReqIdentifier {
		if isSecureInternalResp(resp) {
			return nil, imparser.ErrDropSecureWS
		}
		if sanitized, ok := p.sanitizeSyncedPushMessages(&pushMsg); ok {
			return []imparser.MsgData{
				&MsgData{
					Resp:    cloneResp(resp),
					PushMsg: sanitized,
				},
			}, nil
		}
		return nil, imparser.ErrBypassSecureWS
	}

	items := make([]imparser.MsgData, 0)
	hasSecure := false
	for conversationID, pullMsg := range pushMsg.Msgs {
		if pullMsg == nil {
			continue
		}
		for _, raw := range pullMsg.Msgs {
			if raw == nil {
				continue
			}
			item := &MsgData{
				MsgData:    raw,
				Resp:       cloneResp(resp),
				PushMsg:    singleMessagePush(conversationID, pullMsg, raw),
				SecureRead: false,
			}
			if strings.HasPrefix(raw.Ex, imparser.SecureWSMarker) {
				raw.Ex = strings.TrimPrefix(raw.Ex, imparser.SecureWSMarker)
				item.SecureRead = true
				hasSecure = true
			}
			items = append(items, item)
		}
	}

	if !hasSecure {
		if isSecureInternalResp(resp) {
			return nil, imparser.ErrDropSecureWS
		}
		return nil, imparser.ErrBypassSecureWS
	}
	if len(items) == 0 {
		return nil, errors.New("secure push message not found")
	}
	return items, nil
}

func (p *OpenIMParser) MsgDataToBytesReadBound(msgi imparser.MsgData) ([]byte, error) {
	msgData, ok := msgi.(*MsgData)
	if !ok {
		return nil, fmt.Errorf("invalid MsgData format")
	}
	if msgData == nil {
		return nil, fmt.Errorf("msgData is nil")
	}
	if msgData.MsgData == nil && msgData.PushMsg == nil {
		return nil, fmt.Errorf("inner MsgData and PushMsg are nil")
	}

	var pushMsg *sdkws.PushMessages
	if msgData.PushMsg != nil {
		pushMsg = msgData.PushMsg
	} else {
		pushMsg = &sdkws.PushMessages{
			Msgs: map[string]*sdkws.PullMsgs{
				msgData.RecvID: {
					Msgs: []*sdkws.MsgData{msgData.MsgData},
				},
			},
		}
	}
	if msgData.SecureRead && msgData.Resp != nil && msgData.Resp.ReqIdentifier == realtimePushReqIdentifier {
		p.rememberRealtimePushMessages(pushMsg)
	}

	pushMsgBytes, err := proto.Marshal(pushMsg)
	if err != nil {
		log.Printf("marshal inbound PushMessages failed: %v", err)
		return nil, err
	}

	var resp *Resp
	if msgData.Resp != nil {
		resp = msgData.Resp
		resp.Data = pushMsgBytes
	} else {
		resp = p.constructResp(pushMsgBytes)
	}

	msg, err := p.encodeAndCompressReadBound(resp)
	if err != nil {
		log.Printf("encode inbound response failed: %v", err)
		return nil, err
	}
	return msg, nil
}

func (p *OpenIMParser) sanitizeSyncedPushMessages(pushMsg *sdkws.PushMessages) (*sdkws.PushMessages, bool) {
	if pushMsg == nil || len(pushMsg.Msgs) == 0 {
		return nil, false
	}

	sanitized := &sdkws.PushMessages{
		Msgs: make(map[string]*sdkws.PullMsgs, len(pushMsg.Msgs)),
	}
	removedSecure := false
	for conversationID, pullMsg := range pushMsg.Msgs {
		if pullMsg == nil {
			sanitized.Msgs[conversationID] = nil
			continue
		}

		clonedPullMsg := *pullMsg
		clonedPullMsg.Msgs = make([]*sdkws.MsgData, 0, len(pullMsg.Msgs))
		for _, raw := range pullMsg.Msgs {
			if raw == nil {
				continue
			}
			if strings.HasPrefix(raw.Ex, imparser.SecureWSMarker) {
				removedSecure = true
				if realtimeMsg := p.takeRealtimeMsgData(conversationID, raw); realtimeMsg != nil {
					clonedPullMsg.Msgs = append(clonedPullMsg.Msgs, realtimeMsg)
				}
				continue
			}
			clonedPullMsg.Msgs = append(clonedPullMsg.Msgs, raw)
		}
		sanitized.Msgs[conversationID] = &clonedPullMsg
	}
	if !removedSecure {
		return nil, false
	}
	return sanitized, true
}

func (p *OpenIMParser) rememberRealtimePushMessages(pushMsg *sdkws.PushMessages) {
	if p == nil || pushMsg == nil {
		return
	}
	for conversationID, pullMsg := range pushMsg.Msgs {
		if pullMsg == nil {
			continue
		}
		for _, msg := range pullMsg.Msgs {
			key := realtimeMsgKey(conversationID, msg)
			if key == "" {
				continue
			}
			p.realtimeMsgMap.Store(key, cloneMsgData(msg))
		}
	}
}

func (p *OpenIMParser) takeRealtimeMsgData(conversationID string, msg *sdkws.MsgData) *sdkws.MsgData {
	if p == nil {
		return nil
	}
	key := realtimeMsgKey(conversationID, msg)
	if key == "" {
		return nil
	}
	value, ok := p.realtimeMsgMap.LoadAndDelete(key)
	if !ok {
		return nil
	}
	cached, ok := value.(*sdkws.MsgData)
	if !ok {
		return nil
	}
	return cloneMsgData(cached)
}

func realtimeMsgKey(conversationID string, msg *sdkws.MsgData) string {
	if conversationID == "" || msg == nil {
		return ""
	}
	if msg.Seq != 0 {
		return fmt.Sprintf("%s#seq:%d", conversationID, msg.Seq)
	}
	if msg.ServerMsgID != "" {
		return fmt.Sprintf("%s#server:%s", conversationID, msg.ServerMsgID)
	}
	if msg.ClientMsgID != "" {
		return fmt.Sprintf("%s#client:%s", conversationID, msg.ClientMsgID)
	}
	return ""
}

func cloneMsgData(msg *sdkws.MsgData) *sdkws.MsgData {
	if msg == nil {
		return nil
	}
	if cloned, ok := proto.Clone(msg).(*sdkws.MsgData); ok {
		return cloned
	}
	copied := *msg
	return &copied
}

func singleMessagePush(conversationID string, pullMsg *sdkws.PullMsgs, raw *sdkws.MsgData) *sdkws.PushMessages {
	if conversationID == "" && raw != nil {
		conversationID = raw.RecvID
	}

	clonedPullMsg := &sdkws.PullMsgs{
		Msgs: []*sdkws.MsgData{raw},
	}
	if pullMsg != nil {
		copied := *pullMsg
		copied.Msgs = []*sdkws.MsgData{raw}
		clonedPullMsg = &copied
	}

	return &sdkws.PushMessages{
		Msgs: map[string]*sdkws.PullMsgs{
			conversationID: clonedPullMsg,
		},
	}
}

func (p *OpenIMParser) decodeAndDecompressReadBound(data []byte) (*Resp, error) {
	decompressMsg, err := p.compressor.DecompressWithPool(data)
	if err != nil {
		log.Printf("decompress inbound response failed: %v", err)
		return nil, err
	}

	var resp Resp
	if err := p.encoder.Decode(decompressMsg, &resp); err != nil {
		log.Printf("decode inbound response failed: %v", err)
		return nil, err
	}
	return &resp, nil
}

func (p *OpenIMParser) encodeAndCompressReadBound(resp *Resp) ([]byte, error) {
	encodeData, err := p.encoder.Encode(resp)
	if err != nil {
		return nil, err
	}

	compressData, err := p.compressor.CompressWithPool(encodeData)
	if err != nil {
		return nil, err
	}

	return compressData, nil
}

func (p *OpenIMParser) constructResp(data []byte) *Resp {
	return &Resp{
		ReqIdentifier: 1003,
		OperationID:   uuid.New().String(),
		MsgIncr:       fmt.Sprintf("%d", time.Now().UnixMilli()),
		Data:          data,
	}
}

func cloneResp(resp *Resp) *Resp {
	if resp == nil {
		return nil
	}
	cloned := *resp
	return &cloned
}

func isSecureInternalResp(resp *Resp) bool {
	if resp == nil {
		return false
	}
	return strings.HasPrefix(resp.OperationID, imparser.SecureWSMarker) ||
		strings.HasPrefix(resp.MsgIncr, imparser.SecureWSMarker)
}
