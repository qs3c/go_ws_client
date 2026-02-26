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

// MsgData => []byte
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

	// Req 构造
	req := p.constructReq(msgBytes, msgData.SendID)

	// 编码+压缩
	msg, err := p.encodeAndCompressWriteBound(req)
	if err != nil {
		log.Printf("编码压缩失败: %v", err)
		return nil, err
	}
	return msg, nil
}

// []byte => MsgData
func (p *OpenIMParser) BytesToMsgDataWriteBound(data []byte) (*MsgData, error) {
	// 解压解码
	reqData, err := p.decodeAndDecompressWriteBound(data)
	if err != nil {
		log.Printf("解码压缩失败: %v", err)
		return nil, err
	}

	// 反序列化（指针嵌入，必须先初始化内部指针再传给 proto.Unmarshal）
	// ******************
	msgData := MsgData{MsgData: &sdkws.MsgData{}}
	// unmarshal 是可以接受指针的，但是要注意 nil 指针问题，所以上面先初始化一下
	err = proto.Unmarshal(reqData, msgData.MsgData)
	if err != nil {
		log.Printf("反序列化失败: %v", err)
		return nil, err
	}

	return &msgData, nil
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

func (p *OpenIMParser) encodeAndCompressWriteBound(req *Req) ([]byte, error) {
	// 编码
	encodeData, err := p.encoder.Encode(req)
	if err != nil {
		fmt.Printf("编码失败:%v\n", err)
	}
	// 压缩
	compressData, err := p.compresser.CompressWithPool(encodeData)
	if err != nil {
		fmt.Printf("压缩失败:%v\n", err)
	}

	return compressData, nil

}


func (p *OpenIMParser) decodeAndDecompressWriteBound(data []byte) ([]byte, error) {

	// 解压
	decompressData, err := p.compresser.DecompressWithPool(data)
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
	return req.Data, nil
}
