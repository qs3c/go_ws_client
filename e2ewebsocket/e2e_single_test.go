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

// 两个人互相连续发送多条消息乒乓测试
func TestE2E_PingPong(t *testing.T) {
	cwd, _ := os.Getwd()
	keyStorePath := filepath.Join(filepath.Dir(cwd), "static_key")
	if _, err := os.Stat(keyStorePath); os.IsNotExist(err) {
		t.Skipf("static_key 不存在于 %s", keyStorePath)
	}

	// 启动 Mock Server
	ms := newMockServer()
	s := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer s.Close()
	wsUrl := "ws" + strings.TrimPrefix(s.URL, "http")

	mockComp := &MockCompressor{}
	parser := openimmarshal.NewOpenIMParser(encoder.NewGobEncoder(), mockComp)

	newConn := func(wsURL, hostId string) *Conn {
		conn, err := NewSecureConn(hostId, &Config{
			KeyStorePath: keyStorePath,
			Compressor:   mockComp,
			Encoder:      encoder.NewGobEncoder(),
		}, parser)
		if err != nil {
			t.Fatalf("[%s] NewSecureConn failed: %v", hostId, err)
		}
		_, err = conn.Dial(wsURL+"?uid="+hostId, nil)
		if err != nil {
			t.Fatalf("[%s] Dial failed: %v", hostId, err)
		}
		return conn
	}

	connAlice := newConn(wsUrl, "1111111111")
	defer connAlice.Close()

	connBob := newConn(wsUrl, "2222222222")
	defer connBob.Close()

	// 等待 mock server 把两个连接都加入
	time.Sleep(100 * time.Millisecond)

	// 解码验证
	decodeMsg := func(raw []byte) (string, bool) {
		var recvResp Resp
		dec := encoder.NewGobEncoder()
		if err := dec.Decode(raw, &recvResp); err != nil {
			return "", false
		}
		var pushMsg sdkws.PushMessages
		if err := proto.Unmarshal(recvResp.Data, &pushMsg); err != nil {
			return "", false
		}
		var recvMsgData *sdkws.MsgData
		for _, pull := range pushMsg.Msgs {
			for _, m := range pull.Msgs {
				recvMsgData = m
			}
		}
		if recvMsgData == nil {
			return "", false
		}
		return string(recvMsgData.Content), true
	}

	msgCount := 5
	errCh := make(chan error, 3)

	// Alice 连续发送 msgCount 条消息给 Bob
	go func() {
		for i := 0; i < msgCount; i++ {
			text := fmt.Sprintf("Alice to Bob #%d", i)
			payload := makeAppMsg(t, "1111111111", "2222222222", []byte(text))
			if err := connAlice.WriteMessage(websocket.BinaryMessage, payload); err != nil {
				errCh <- fmt.Errorf("Alice WriteMessage failed: %v", err)
				return
			}
			t.Logf("Alice: sent '%s'", text)
			time.Sleep(10 * time.Millisecond) // 稍微错峰
		}
		errCh <- nil
	}()

	// Bob 接收 msgCount 条并回复
	go func() {
		for i := 0; i < msgCount; i++ {
			_, msg, err := connBob.ReadMessage()
			if err != nil {
				errCh <- fmt.Errorf("Bob ReadMessage failed: %v", err)
				return
			}
			text, ok := decodeMsg(msg)
			if !ok {
				errCh <- fmt.Errorf("Bob decode failed")
				return
			}
			t.Logf("Bob: received '%s'", text)

			replyText := fmt.Sprintf("Bob reply to [%s]", text)
			replyPayload := makeAppMsg(t, "2222222222", "1111111111", []byte(replyText))
			if err := connBob.WriteMessage(websocket.BinaryMessage, replyPayload); err != nil {
				errCh <- fmt.Errorf("Bob WriteMessage failed: %v", err)
				return
			}
		}
		errCh <- nil
	}()

	// Alice 收回包
	go func() {
		for i := 0; i < msgCount; i++ {
			_, msg, err := connAlice.ReadMessage()
			if err != nil {
				errCh <- fmt.Errorf("Alice ReadMessage failed: %v", err)
				return
			}
			text, ok := decodeMsg(msg)
			if !ok {
				errCh <- fmt.Errorf("Alice decode reply failed")
				return
			}
			t.Logf("Alice: received reply '%s'", text)
		}
		errCh <- nil
	}()

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()

	// 收集 3 个协程的退出状态
	for i := 0; i < 3; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatal(err)
			}
		case <-timer.C:
			t.Fatal("Timeout waiting for ping-pong message exchange")
		}
	}

	t.Log("TestE2E_PingPong PASSED")
}
