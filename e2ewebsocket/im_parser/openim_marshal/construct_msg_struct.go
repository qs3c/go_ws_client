package openimmarshal

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/openimsdk/protocol/sdkws"
)

var offlinePushInfo = &sdkws.OfflinePushInfo{
	Title:         "You have a new message.",
	IOSPushSound:  "+1",
	IOSBadgeCount: true,
	// 其他未提及的字段默认空值
}

func ConstructMsgData(sendID, recvID string, msg []byte) *MsgData {

	clientMsgID, err := randomString(32)
	if err != nil {
		fmt.Printf("生成clientMsgID失败:%v\n", err)
	}

	msgData := &MsgData{
		MsgData: &sdkws.MsgData{
			SendID:           sendID,                 // 对应打印结果中的 sendID "4467602324"
			RecvID:           recvID,                 // recvID "6830464723"
			ClientMsgID:      clientMsgID,            // clientMsgID "随机生成一个32个字符的string"
			SenderPlatformID: 5,                      //  senderPlatformID
			SenderNickname:   "***",                  //  senderNickname
			SessionType:      1,                      // 对应打印结果中的 sessionType
			MsgFrom:          100,                    // 对应打印结果中的 msgFrom
			ContentType:      101,                    // 对应打印结果中的 contentType
			Content:          msg,                    // content
			CreateTime:       time.Now().UnixMilli(), // createTime int64
			Status:           1,                      // 对应打印结果中的 status
			OfflinePushInfo:  offlinePushInfo,        // 关联上面填充的 OfflinePushInfo
			AttachedInfo:     "null",                 // 对应打印结果中的 attachedInfo
			// 其他未提及的字段默认空値（如 GroupID、ServerMsgID 等）
		},
	}
	return msgData
}

// 1 握手消息
func ConstructHandshakeMsg(sendID, recvID string, msg []byte) *MsgData {
	return ConstructMsgData(sendID, recvID, msg)
}

// 2. CCS 消息
func ConstructCCSMsg(sendID, recvID string) *MsgData {
	return ConstructMsgData(sendID, recvID, []byte("CCS"))
}

// 3. Alter 消息
func ConstructAlterMsg(sendID, recvID string) *MsgData {
	return ConstructMsgData(sendID, recvID, []byte("Alter"))
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
