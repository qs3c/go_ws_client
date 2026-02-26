package openimmarshal

import (
	"errors"
	"fmt"
	"log"

	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
)

// MsgData => []byte（MsgDataFromServerReadBound 的逆过程）
func (p *OpenIMParser) MsgDataToBytesServerReadBound(msgData *MsgData) ([]byte, error) {
	if msgData == nil || msgData.MsgData == nil {
		return nil, fmt.Errorf("msgData 或其内部 MsgData 为 nil")
	}

	// 逆过程第一步：将 MsgData 包装进 PushMessages
	// From 函数中取的是 pushMsg.Msgs[key].Msgs[0]，所以这里反向构造
	// map 的 key 在 OpenIM 单聊中通常为 RecvID
	pushMsg := &sdkws.PushMessages{
		Msgs: map[string]*sdkws.PullMsgs{
			msgData.RecvID: {
				Msgs: []*sdkws.MsgData{msgData.MsgData},
			},
		},
	}

	// 逆过程第二步：proto.Marshal(PushMessages) => pushMsgBytes
	// 对应 From 函数中的 proto.Unmarshal(respData, &pushMsg)
	pushMsgBytes, err := proto.Marshal(pushMsg)
	if err != nil {
		log.Printf("序列化 PushMessages 失败: %v", err)
		return nil, err
	}

	// 逆过程第三步：放入 Resp.Data，编码+压缩
	// 对应 From 函数中的 解压 → 解码(Resp) → resp.Data
	resp := &Resp{Data: pushMsgBytes}
	encodeData, err := p.encoder.Encode(resp)
	if err != nil {
		log.Printf("编码失败: %v", err)
		return nil, err
	}
	compressData, err := p.compresser.CompressWithPool(encodeData)
	if err != nil {
		log.Printf("压缩失败: %v", err)
		return nil, err
	}
	return compressData, nil
}

// []byte => MsgData
func (p *OpenIMParser) BytesToMsgDataReadBound(data []byte) (*MsgData, error) {

	respData, err := p.decodeAndDecompressReadBound(data)
	if err != nil {
		log.Printf("解码压缩失败: %v", err)
		return nil, err
	}

	var pushMsg sdkws.PushMessages
	// 反序列化到 PushMessages 结构体
	err = proto.Unmarshal(respData, &pushMsg)
	if err != nil {
		log.Printf("反序列化消息失败: %v", err)
		return nil, err
	}

	msgMap := pushMsg.Msgs
	// 虽然是循环，但是单聊的时候 map 里只会有一个会话
	for _, pullMsg := range msgMap {
		// 一个会话里可能有多个消息，但单聊的时候一般只有一个
		for _, msgData := range pullMsg.Msgs {
			return &MsgData{MsgData: msgData}, nil
		}
	}
	return nil, errors.New("未找到消息")

}

func (p *OpenIMParser) decodeAndDecompressReadBound(data []byte) ([]byte, error) {
	// 解压
	decompressMsg, err := p.compresser.DecompressWithPool(data)
	if err != nil {
		log.Printf("解压消息失败: %v", err)
		return nil, err
	}

	// 解码
	var resp Resp
	err = p.encoder.Decode(decompressMsg, &resp)
	if err != nil {
		log.Printf("解码消息失败: %v", err)
		return nil, err
	}
	return resp.Data, nil
}
