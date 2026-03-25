package openimmarshal

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
)

// var (
// 	msgEncoder    encoder.Encoder       = encoder.NewJsonEncoder()
// 	msgCompressor compressor.Compressor = compressor.NewGzipCompressor()
// )

// WriteBound 是 =>Server 方向的，与 Req 打交道

// []byte => MsgData 【反解出来拿Content去加密】
func (p *OpenIMParser) BytesToMsgDataWriteBound(data []byte) (*MsgData, error) {
	// 解压解码
	req, err := p.decodeAndDecompressWriteBound(data)
	if err != nil {
		log.Printf("解码压缩失败: %v", err)
		return nil, err
	}

	// 反序列化（指针嵌入，必须先初始化内部指针再传给 proto.Unmarshal）
	// ******************
	msgData := MsgData{
		MsgData: &sdkws.MsgData{},
		Req:     req,
	}
	// unmarshal 是可以接受指针的，但是要注意 nil 指针问题，所以上面先初始化一下
	err = proto.Unmarshal(req.Data, msgData.MsgData)
	if err != nil {
		log.Printf("反序列化失败: %v", err)
		return nil, err
	}

	return &msgData, nil
}

// MsgData => []byte 【加密完Content再重新序列化】
func (p *OpenIMParser) MsgDataToBytesWriteBound(msgData *MsgData) ([]byte, error) {
	// ******************
	if msgData == nil || msgData.MsgData == nil {
		return nil, fmt.Errorf("msgData 或其内部 MsgData 为 nil")
	}

	msgBytes, err := proto.Marshal(msgData.MsgData)
	if err != nil {
		log.Printf("序列化消息失败: %v", err)
		return nil, err
	}

	// Req 直接用之前解析得到的，没有才走构造
	var req *Req
	if msgData.Req != nil {
		req = msgData.Req
		req.Data = msgBytes
	} else {
		req = p.constructReq(msgBytes, msgData.SendID)
	}

	// 编码+压缩
	msg, err := p.encodeAndCompressWriteBound(req)
	if err != nil {
		log.Printf("编码压缩失败: %v", err)
		return nil, err
	}
	return msg, nil
}

func (p *OpenIMParser) decodeAndDecompressWriteBound(data []byte) (*Req, error) {

	// 解压
	decompressData, err := p.compressor.DecompressWithPool(data)
	if err != nil {
		log.Printf("解压失败: %v", err)
		return nil, err
	}

	// 解码
	var req Req
	err = p.encoder.Decode(decompressData, &req)
	if err != nil {
		log.Printf("解码失败: %v", err)
		return nil, err
	}
	return &req, nil
}

func (p *OpenIMParser) encodeAndCompressWriteBound(req *Req) ([]byte, error) {
	// 编码
	encodeData, err := p.encoder.Encode(req)
	if err != nil {
		fmt.Printf("编码失败:%v\n", err)
	}
	// 压缩
	compressData, err := p.compressor.CompressWithPool(encodeData)
	if err != nil {
		fmt.Printf("压缩失败:%v\n", err)
	}

	return compressData, nil

}

func (p *OpenIMParser) constructReq(data []byte, sendId string) *Req {
	return &Req{
		ReqIdentifier: 1003,
		Token:         "",
		SendID:        sendId,
		OperationID:   uuid.New().String(),
		MsgIncr:       fmt.Sprintf("%s_%d", sendId, time.Now().UnixMilli()),
		Data:          data,
	}
}
