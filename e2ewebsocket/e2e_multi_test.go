package e2ewebsocket

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albert/ws_client/encoder"
	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
	openimmarshal "github.com/albert/ws_client/e2ewebsocket/im_parser/openim_marshal"
)

// TestE2E_MultiPeer 测试 Alice 同时与 Bob 和 Catherine 进行 E2E 加密通信。
//
// Alice 使用单个 Conn 对象并发运行，分别代表她与 Bob 和与 Catherine 的会话。
// 两组会话完全并发，共用一条 WebSocket 物理连接通道，互不干扰。
//
// 验证点：
//   - Alice ↔ Bob E2E 握手、加密通信
//   - Alice ↔ Catherine E2E 握手、加密通信
//   - 两组会话并发运行，密码互不干扰
func TestE2E_MultiPeer(t *testing.T) {
	// 1. 检查密钥目录
	cwd, _ := os.Getwd()
	keyStorePath := filepath.Join(filepath.Dir(cwd), "static_key")
	if _, err := os.Stat(keyStorePath); os.IsNotExist(err) {
		t.Skipf("static_key 目录不存在（%s），请先运行 TestGenKeys 生成密钥", keyStorePath)
	}
	if _, err := os.Stat(filepath.Join(keyStorePath, "3333333333")); os.IsNotExist(err) {
		t.Skipf("未找到 Catherine 的密钥目录（3333333333），请先运行 TestGenKeys 生成密钥")
	}

	// 2. 辅助函数：建立安全连接
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
			t.Fatalf("[%s] Dial(%s) failed: %v", hostId, wsURL, err)
		}
		return conn
	}

	// 3. 启动一专属 mock server
	// ── Server：所有连接共享一个 server，基于精确路由投递 ───────────────────
	srv := httptest.NewServer(http.HandlerFunc(newMockServer().handler))
	defer srv.Close()
	url := "ws" + strings.TrimPrefix(srv.URL, "http")

	// 4. 各方连接
	connAlice := newConn(url, "1111111111") // Alice 核心单连接
	defer connAlice.Close()

	connBob := newConn(url, "2222222222") // Bob 连接
	defer connBob.Close()

	connCatherine := newConn(url, "3333333333") // Catherine 连接
	defer connCatherine.Close()

	// 等待 mock server 注册完所有连接
	time.Sleep(100 * time.Millisecond)

	const msgCount = 3

	// decodeMsg 解析收到的原始字节并返回文本内容
	decodeMsg := func(raw []byte) (string, bool) {
		var resp Resp
		if err := encoder.NewGobEncoder().Decode(raw, &resp); err != nil {
			return "", false
		}
		var pushMsg sdkws.PushMessages
		if err := proto.Unmarshal(resp.Data, &pushMsg); err != nil {
			return "", false
		}
		var md *sdkws.MsgData
		for _, pull := range pushMsg.Msgs {
			for _, m := range pull.Msgs {
				md = m
			}
		}
		if md == nil {
			return "", false
		}
		return string(md.Content), true
	}

	var wg sync.WaitGroup

	// ── 并发发送：Alice → Bob / Catherine ───────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < msgCount; i++ {
			// 发给 Bob
			payloadBob := makeAppMsg(t, "1111111111", "2222222222",
				[]byte(fmt.Sprintf("Alice to Bob #%d", i)))
			if err := connAlice.WriteMessage(websocket.BinaryMessage, payloadBob); err != nil {
				t.Errorf("Alice → Bob write[%d] failed: %v", i, err)
			}
            
			// 发给 Catherine
			payloadCat := makeAppMsg(t, "1111111111", "3333333333",
				[]byte(fmt.Sprintf("Alice to Catherine #%d", i)))
			if err := connAlice.WriteMessage(websocket.BinaryMessage, payloadCat); err != nil {
				t.Errorf("Alice → Catherine write[%d] failed: %v", i, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// ── 接收并回复：Bob ──────────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		received := 0
		for received < msgCount {
			_, raw, err := connBob.ReadMessage()
			if err != nil {
				t.Errorf("Bob ReadMessage failed: %v", err)
				return
			}
			text, ok := decodeMsg(raw)
			if !ok {
				continue
			}
			received++
			t.Logf("Bob received[%d]: %s", received, text)
			replyPayload := makeAppMsg(t, "2222222222", "1111111111",
				[]byte(fmt.Sprintf("Bob reply: %s", text)))
			if err := connBob.WriteMessage(websocket.BinaryMessage, replyPayload); err != nil {
				t.Errorf("Bob reply[%d] failed: %v", received, err)
				return
			}
		}
		t.Logf("Bob: replied %d messages", received)
	}()

    // ── 接收并回复：Catherine ────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		received := 0
		for received < msgCount {
			_, raw, err := connCatherine.ReadMessage()
			if err != nil {
				t.Errorf("Catherine ReadMessage failed: %v", err)
				return
			}
			text, ok := decodeMsg(raw)
			if !ok {
				continue
			}
			received++
			t.Logf("Catherine received[%d]: %s", received, text)
			replyPayload := makeAppMsg(t, "3333333333", "1111111111",
				[]byte(fmt.Sprintf("Catherine reply: %s", text)))
			if err := connCatherine.WriteMessage(websocket.BinaryMessage, replyPayload); err != nil {
				t.Errorf("Catherine reply[%d] failed: %v", received, err)
				return
			}
		}
		t.Logf("Catherine: replied %d messages", received)
	}()

	// ── 统一收取回包：Alice ──────────────────────────────────────────────
	wg.Add(1)
	go func() {
		defer wg.Done()
		receivedBob := 0
		receivedCat := 0
		for (receivedBob + receivedCat) < msgCount*2 {
			_, raw, err := connAlice.ReadMessage()
			if err != nil {
				t.Errorf("Alice ReadMessage failed: %v", err)
				return
			}
			text, ok := decodeMsg(raw)
			if !ok {
				continue
			}
			if strings.Contains(text, "Bob reply") {
				receivedBob++
				t.Logf("Alice ← Bob reply[%d]: %s", receivedBob, text)
			} else if strings.Contains(text, "Catherine reply") {
				receivedCat++
				t.Logf("Alice ← Catherine reply[%d]: %s", receivedCat, text)
			}
		}
	}()

	// 5. 等待所有 goroutine 完成，或超时
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Log("TestE2E_MultiPeer PASSED - Alice 使用单条连接与 Bob 和 Catherine 并发通信均成功")
	case <-time.After(15 * time.Second):
		t.Fatal("TestE2E_MultiPeer timed out")
	}
}
