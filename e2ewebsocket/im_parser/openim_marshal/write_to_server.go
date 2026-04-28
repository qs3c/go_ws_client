package openimmarshal

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/openimsdk/protocol/sdkws"
	imparser "github.com/qs3c/e2e-secure-ws/e2ewebsocket/im_parser"
	"google.golang.org/protobuf/proto"
)

const secureTextContentType int32 = 101

// BytesToMsgDataWriteBound converts an outbound OpenIM websocket request into
// MsgData only for SendMsg requests. All other request types should bypass the
// secure overlay and go through the original OpenIM protocol unchanged.
func (p *OpenIMParser) BytesToMsgDataWriteBound(data []byte) (imparser.MsgData, error) {
	req, err := p.decodeAndDecompressWriteBound(data)
	if err != nil {
		log.Printf("decode outbound request failed: %v", err)
		return nil, err
	}
	if req.ReqIdentifier != 1003 {
		return nil, imparser.ErrBypassSecureWS
	}

	msgData := MsgData{
		MsgData: &sdkws.MsgData{},
		Req:     req,
	}
	if err := proto.Unmarshal(req.Data, msgData.MsgData); err != nil {
		return nil, imparser.ErrBypassSecureWS
	}
	if !shouldSecureOutbound(msgData.MsgData) {
		return nil, imparser.ErrBypassSecureWS
	}

	return &msgData, nil
}

// MsgDataToBytesWriteBound writes the encrypted MsgData back into the original
// OpenIM request envelope so the outer websocket payload remains protocol
// compatible with the stock OpenIM server.
func (p *OpenIMParser) MsgDataToBytesWriteBound(msgi imparser.MsgData) ([]byte, error) {
	msgData, ok := msgi.(*MsgData)
	if !ok {
		return nil, fmt.Errorf("invalid MsgData format")
	}
	if msgData == nil || msgData.MsgData == nil {
		return nil, fmt.Errorf("msgData or inner MsgData is nil")
	}

	msgBytes, err := proto.Marshal(msgData.MsgData)
	if err != nil {
		log.Printf("marshal outbound MsgData failed: %v", err)
		return nil, err
	}

	var req *Req
	if msgData.Req != nil {
		req = msgData.Req
		req.Data = msgBytes
	} else {
		req = p.constructReq(msgBytes, msgData.SendID)
	}

	msg, err := p.encodeAndCompressWriteBound(req)
	if err != nil {
		log.Printf("encode outbound request failed: %v", err)
		return nil, err
	}
	return msg, nil
}

func (p *OpenIMParser) decodeAndDecompressWriteBound(data []byte) (*Req, error) {
	decompressData, err := p.compressor.DecompressWithPool(data)
	if err != nil {
		log.Printf("decompress outbound request failed: %v", err)
		return nil, err
	}

	var req Req
	if err := p.encoder.Decode(decompressData, &req); err != nil {
		log.Printf("decode outbound request failed: %v", err)
		return nil, err
	}
	return &req, nil
}

func (p *OpenIMParser) encodeAndCompressWriteBound(req *Req) ([]byte, error) {
	encodeData, err := p.encoder.Encode(req)
	if err != nil {
		return nil, err
	}
	compressData, err := p.compressor.CompressWithPool(encodeData)
	if err != nil {
		return nil, err
	}
	return compressData, nil
}

func (p *OpenIMParser) constructReq(data []byte, sendID string) *Req {
	operationID := imparser.SecureWSMarker + uuid.New().String()
	msgIncr := imparser.SecureWSMarker + fmt.Sprintf("%s_%d", sendID, time.Now().UnixMilli())
	return &Req{
		ReqIdentifier: 1003,
		Token:         "",
		SendID:        sendID,
		OperationID:   operationID,
		MsgIncr:       msgIncr,
		Data:          data,
	}
}

func shouldSecureOutbound(msgData *sdkws.MsgData) bool {
	if msgData == nil {
		return false
	}
	if msgData.SendID == "" || msgData.RecvID == "" {
		return false
	}
	if msgData.SessionType != 1 {
		return false
	}
	return msgData.ContentType == secureTextContentType
}
