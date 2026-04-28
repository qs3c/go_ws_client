package openimmarshal

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/openimsdk/protocol/sdkws"
	imparser "github.com/qs3c/e2e-secure-ws/e2ewebsocket/im_parser"
)

var secureControlOptions = map[string]bool{
	"history":                  false,
	"persistent":               false,
	"unreadCount":              false,
	"conversationUpdate":       false,
	"offlinePush":              false,
	"senderSync":               false,
	"notPrivate":               false,
	"senderConversationUpdate": false,
}

func (p *OpenIMParser) ConstructMsgData(sendID, recvID string, msg []byte) imparser.MsgData {
	clientMsgID, err := randomString(32)
	if err != nil {
		fmt.Printf("generate clientMsgID failed: %v\n", err)
	}

	msgData := &MsgData{
		MsgData: &sdkws.MsgData{
			SendID:           sendID,
			RecvID:           recvID,
			ClientMsgID:      clientMsgID,
			SenderPlatformID: 5,
			SenderNickname:   "secure-ws",
			SessionType:      1,
			MsgFrom:          100,
			ContentType:      secureTextContentType,
			Content:          msg,
			CreateTime:       time.Now().UnixMilli(),
			Status:           1,
			Options:          cloneSecureControlOptions(),
			AttachedInfo:     "null",
		},
	}
	return msgData
}

func cloneSecureControlOptions() map[string]bool {
	options := make(map[string]bool, len(secureControlOptions))
	for key, value := range secureControlOptions {
		options[key] = value
	}
	return options
}

func randomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	charsetLen := big.NewInt(int64(len(charset)))

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		randomIndex, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", fmt.Errorf("generate random value failed: %w", err)
		}
		result[i] = charset[randomIndex.Int64()]
	}

	return string(result), nil
}
