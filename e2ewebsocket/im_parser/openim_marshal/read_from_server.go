package openimmarshal

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
	imparser "github.com/albert/ws_client/e2ewebsocket/im_parser"
)

// ReadBound 是 Server=> 方向的，与 Resp 打交道

// []byte => MsgData 【先解出来拿Content去解密】
func (p *OpenIMParser) BytesToMsgDataReadBound(data []byte) (imparser.MsgData, error) {

	resp, err := p.decodeAndDecompressReadBound(data)
	if err != nil {
		log.Printf("解码压缩失败: %v", err)
		return nil, err
	}

	var pushMsg sdkws.PushMessages
	// 反序列化到 PushMessages 结构体
	err = proto.Unmarshal(resp.Data, &pushMsg)
	if err != nil {
		log.Printf("反序列化消息失败: %v", err)
		return nil, err
	}

	msgMap := pushMsg.Msgs
	// 虽然是循环，但是单聊的时候 map 里只会有一个会话
	for _, pullMsg := range msgMap {
		// 一个会话里可能有多个消息，但单聊的时候一般只有一个
		for _, msgData := range pullMsg.Msgs {
			return &MsgData{MsgData: msgData, Resp: resp, PushMsg: &pushMsg}, nil
		}
	}
	return nil, errors.New("未找到消息")

}

// MsgData => []byte 【解密完Content再重新序列化提供给上层】
func (p *OpenIMParser) MsgDataToBytesReadBound(msgi imparser.MsgData) ([]byte, error) {
	msgData, ok := msgi.(*MsgData)
	if !ok {
		return nil, fmt.Errorf("invalid MsgData format")
	}
	if msgData == nil || msgData.MsgData == nil {
		return nil, fmt.Errorf("msgData 或其内部 MsgData 为 nil")
	}

	// 逆过程第一步：将 MsgData 包装进 PushMessages
	// From 函数中取的是 pushMsg.Msgs[key].Msgs[0]，所以这里反向构造
	// map 的 key 在 OpenIM 单聊中通常为 RecvID
	var pushMsg *sdkws.PushMessages
	if msgData.PushMsg != nil {
		pushMsg = msgData.PushMsg
		// pushMsg.Msgs[msgData.RecvID].Msgs[0] = msgData.MsgData
	} else {
		pushMsg = &sdkws.PushMessages{
			Msgs: map[string]*sdkws.PullMsgs{
				msgData.RecvID: {
					Msgs: []*sdkws.MsgData{msgData.MsgData},
				},
			},
		}
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
	var resp *Resp
	if msgData.Resp != nil {
		resp = msgData.Resp
		resp.Data = pushMsgBytes
	} else {
		// resp = &Resp{Data: pushMsgBytes}
		resp = p.constructResp(pushMsgBytes)
	}
	msg, err := p.encodeAndCompressReadBound(resp)
	if err != nil {
		log.Printf("编码压缩失败: %v", err)
		return nil, err
	}
	return msg, nil
}

func (p *OpenIMParser) decodeAndDecompressReadBound(data []byte) (*Resp, error) {
	// 解压
	decompressMsg, err := p.compressor.DecompressWithPool(data)
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
	return &resp, nil
}

func (p *OpenIMParser) encodeAndCompressReadBound(resp *Resp) ([]byte, error) {
	// 压缩
	encodeData, err := p.encoder.Encode(resp)
	if err != nil {
		log.Printf("编码失败: %v", err)
		return nil, err
	}

	// 编码
	compressData, err := p.compressor.CompressWithPool(encodeData)
	if err != nil {
		log.Printf("压缩失败: %v", err)
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
