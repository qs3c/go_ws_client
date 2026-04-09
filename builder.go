package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/qs3c/e2e-secure-ws/compressor"
	"github.com/qs3c/e2e-secure-ws/encoder"
	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"github.com/openimsdk/protocol/sdkws"
)

type Builder struct {
	sendID         string
	recvID         string
	senderNickname string

	offlinePushInfo *sdkws.OfflinePushInfo
	msgData         *sdkws.MsgData
	req             *Req

	encoder    encoder.Encoder
	compressor compressor.Compressor
}

func NewBuilder(sendID string, recvID string, senderNickname string, encoder encoder.Encoder, compressor compressor.Compressor) *Builder {
	return &Builder{
		sendID:         sendID,
		recvID:         recvID,
		senderNickname: senderNickname,
		encoder:        encoder,
		compressor:     compressor,
	}
}

func (b *Builder) OfflinePushInfo() *Builder {
	b.offlinePushInfo = &sdkws.OfflinePushInfo{
		Title:         "You have a new message.",
		IOSPushSound:  "+1",
		IOSBadgeCount: true,
		// 其他未提及的字段默认空值
	}

	return b
}

func (b *Builder) MsgData(msg string) *Builder {

	clientMsgID, err := randomString(32)
	if err != nil {
		fmt.Printf("生成clientMsgID失败:%v\n", err)
	}

	b.msgData = &sdkws.MsgData{
		SendID:           b.sendID,                            // 对应打印结果中的 sendID "4467602324"
		RecvID:           b.recvID,                            // recvID "6830464723"
		ClientMsgID:      clientMsgID,                         // clientMsgID "805a55386e8924c8058bc46b9782e1b7" 随机生成一个32个字符的string
		SenderPlatformID: 5,                                   //  senderPlatformID
		SenderNickname:   b.senderNickname,                    //  senderNickname "chenshaobo"
		SessionType:      1,                                   // 对应打印结果中的 sessionType
		MsgFrom:          100,                                 // 对应打印结果中的 msgFrom
		ContentType:      101,                                 // 对应打印结果中的 contentType
		Content:          []byte(`{"content":"` + msg + `"}`), // content
		CreateTime:       time.Now().UnixMilli(),              // createTime 1764820495462 int64
		Status:           1,                                   // 对应打印结果中的 status
		OfflinePushInfo:  b.offlinePushInfo,                   // 关联上面填充的 OfflinePushInfo
		AttachedInfo:     "null",                              // 对应打印结果中的 attachedInfo
		// 其他未提及的字段默认空值（如 GroupID、ServerMsgID 等）
	}
	return b
}

func (b *Builder) Req(data []byte) *Builder {
	b.req = &Req{
		ReqIdentifier: 1003,
		Token:         "",
		SendID:        b.sendID,
		OperationID:   uuid.New().String(),
		MsgIncr:       fmt.Sprintf("%s_%d", b.sendID, time.Now().UnixMilli()),
		Data:          data,
	}

	return b
}

func (b *Builder) Build() []byte {
	// 编码
	encodeData, err := b.encoder.Encode(b.req)
	if err != nil {
		fmt.Printf("编码失败:%v\n", err)
	}
	// 压缩
	compressData, err := b.compressor.CompressWithPool(encodeData)
	if err != nil {
		fmt.Printf("压缩失败:%v\n", err)
	}

	return compressData

}

func (b *Builder) UnBuild(compressData []byte) error {

	// 解压压缩数据
	encodeData, err := b.compressor.DecompressWithPool(compressData)
	if err != nil {
		fmt.Printf("解压缩失败:%v\n", err)
	}

	// 解码
	var req Req
	err = b.encoder.Decode(encodeData, &req)
	if err != nil {
		fmt.Printf("解码失败:%v\n", err)
		return err
	}
	// 检查解码后的req是否与原始req一致
	if !cmp.Equal(req, *b.req) {
		fmt.Printf("解码后的req与原始req不一致:%v\n", req)
		return fmt.Errorf("解码后的req与原始req不一致")
	}
	return nil

}

func randomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	charsetLen := big.NewInt(int64(len(charset)))

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("生成随机数失败: %w", err)
		}
		result[i] = charset[randomIndex.Int64()]
	}

	return string(result), nil
}
