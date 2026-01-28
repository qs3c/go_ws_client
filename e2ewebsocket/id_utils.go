package e2ewebsocket

import (
	"bytes"
	"strings"
)

const (
	senderIDLength  = 10
	recordHeaderLen = 1 + senderIDLength
)

func trimSenderID(raw []byte) string {
	return string(bytes.TrimRight(raw, "\x00"))
}

func isInitiator(localID, remoteID string) bool {
	return strings.Compare(localID, remoteID) > 0
}
