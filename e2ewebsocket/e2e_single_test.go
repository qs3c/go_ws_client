package e2ewebsocket

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albert/ws_client/encoder"
	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
	openimmarshal "github.com/albert/ws_client/e2ewebsocket/im_parser/openim_marshal"
)

// 极简单次握手 + 一条消息测试
func TestE2E_SingleMessage(t *testing.T) {
	cwd, _ := os.Getwd()
	keyStorePath := filepath.Join(filepath.Dir(cwd), "static_key")
	if _, err := os.Stat(keyStorePath); os.IsNotExist(err) {
		t.Skipf("static_key 不存在于 %s", keyStorePath)
	}

	// 启动 Mock Server（广播模式）
	ms := newMockServer()
	s := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer s.Close()
	wsUrl := "ws" + strings.TrimPrefix(s.URL, "http")

	mockComp := &MockCompressor{}
	cfgAlice := &Config{KeyStorePath: keyStorePath, Compressor: mockComp, Encoder: encoder.NewGobEncoder()}
	cfgBob := &Config{KeyStorePath: keyStorePath, Compressor: mockComp, Encoder: encoder.NewGobEncoder()}

	wsAlice, _, err := websocket.DefaultDialer.Dial(wsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	parser := openimmarshal.NewOpenIMParser(encoder.NewGobEncoder(), mockComp)
	connAlice, err := NewSecureConn(wsAlice, "1111111111", cfgAlice, parser)
	if err != nil {
		t.Fatal(err)
	}
	defer connAlice.Close()

	wsBob, _, err := websocket.DefaultDialer.Dial(wsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	connBob, err := NewSecureConn(wsBob, "2222222222", cfgBob, parser)
	if err != nil {
		t.Fatal(err)
	}
	defer connBob.Close()

	// 等待 mock server 把两个连接都加入
	time.Sleep(100 * time.Millisecond)

	// Alice 发一条消息给 Bob
	msgData := &sdkws.MsgData{
		SendID:      "1111111111",
		RecvID:      "2222222222",
		Content:     []byte("hello from alice"),
		SessionType: 1,
		MsgFrom:     100,
		ContentType: 101,
	}
	dataBytes, _ := proto.Marshal(msgData)
	req := Req{Data: dataBytes}
	enc := encoder.NewGobEncoder()
	payload, err := enc.Encode(req)
	if err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		fmt.Println("Alice: sending message...")
		if err := connAlice.WriteMessage(websocket.BinaryMessage, payload); err != nil {
			errCh <- fmt.Errorf("Alice WriteMessage failed: %v", err)
			return
		}
		fmt.Println("Alice: message sent successfully")
		errCh <- nil
	}()

	// Bob 接收
	recvCh := make(chan []byte, 1)
	go func() {
		fmt.Println("Bob: waiting for message...")
		_, msg, err := connBob.ReadMessage()
		if err != nil {
			errCh <- fmt.Errorf("Bob ReadMessage failed: %v", err)
			return
		}
		recvCh <- msg
	}()

	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()

	var sendErr error
	var recvMsg []byte
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatal(err)
			}
			sendErr = nil
		case msg := <-recvCh:
			recvMsg = msg
		case <-timer.C:
			t.Fatal("Timeout waiting for message exchange")
		}
	}

	_ = sendErr
	if recvMsg == nil {
		t.Fatal("Bob did not receive message")
	}

	// 解码验证
	var recvResp Resp
	dec := encoder.NewGobEncoder()
	if err := dec.Decode(recvMsg, &recvResp); err != nil {
		t.Fatalf("Bob decode failed: %v", err)
	}
	var pushMsg sdkws.PushMessages
	if err := proto.Unmarshal(recvResp.Data, &pushMsg); err != nil {
		t.Fatalf("Bob unmarshal failed: %v", err)
	}
	var recvMsgData *sdkws.MsgData
	for _, pull := range pushMsg.Msgs {
		for _, m := range pull.Msgs {
			recvMsgData = m
		}
	}
	if recvMsgData == nil {
		t.Fatalf("Bob received empty messages")
	}
	if string(recvMsgData.Content) != "hello from alice" {
		t.Fatalf("content mismatch: got %s", recvMsgData.Content)
	}
	t.Log("TestE2E_SingleMessage PASSED")
}
