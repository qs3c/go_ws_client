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

// BytesToMsgDataReadBound only intercepts PushMsg responses that carry the
// secure marker. All other OpenIM responses should bypass the secure overlay
// and be handled by the original SDK pipeline.
func (p *OpenIMParser) BytesToMsgDataReadBound(data []byte) (imparser.MsgData, error) {
	resp, err := p.decodeAndDecompressReadBound(data)
	if err != nil {
		log.Printf("decode inbound response failed: %v", err)
		return nil, err
	}
	if resp.ReqIdentifier != 2001 {
		if isSecureInternalResp(resp) {
			return nil, imparser.ErrDropSecureWS
		}
		return nil, imparser.ErrBypassSecureWS
	}

	var pushMsg sdkws.PushMessages
	if err := proto.Unmarshal(resp.Data, &pushMsg); err != nil {
		return nil, imparser.ErrBypassSecureWS
	}

	for _, pullMsg := range pushMsg.Msgs {
		for _, raw := range pullMsg.Msgs {
			if raw == nil {
				continue
			}
			if !strings.HasPrefix(raw.Ex, imparser.SecureWSMarker) {
				return nil, imparser.ErrBypassSecureWS
			}
			raw.Ex = strings.TrimPrefix(raw.Ex, imparser.SecureWSMarker)
			return &MsgData{MsgData: raw, Resp: resp, PushMsg: &pushMsg}, nil
		}
	}

	return nil, errors.New("secure push message not found")
}

// MsgDataToBytesReadBound writes the decrypted MsgData back into the original
// PushMsg response envelope.
func (p *OpenIMParser) MsgDataToBytesReadBound(msgi imparser.MsgData) ([]byte, error) {
	msgData, ok := msgi.(*MsgData)
	if !ok {
		return nil, fmt.Errorf("invalid MsgData format")
	}
	if msgData == nil || msgData.MsgData == nil {
		return nil, fmt.Errorf("msgData or inner MsgData is nil")
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

func isSecureInternalResp(resp *Resp) bool {
	if resp == nil {
		return false
	}
	return strings.HasPrefix(resp.OperationID, imparser.SecureWSMarker) ||
		strings.HasPrefix(resp.MsgIncr, imparser.SecureWSMarker)
}
