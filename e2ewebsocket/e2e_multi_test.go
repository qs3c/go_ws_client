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
)

// TestE2E_MultiPeer 测试 Alice 同时与 Bob 和 Catherine 进行 E2E 加密通信。
//
// 由于当前 wire 格式中消息头不含 recvId，单台广播 mock server 无法精准路由消息，
// 会导致第三方（如 Bob 收到 Alice→Catherine 的包）解密失败并发送 alert，
// 从而终止对端的正常 session。
//
// "作弊"方案：给每对通信双方分配一台独立的 mock server。
//
//	server_AB  → Alice(connAB) + Bob     （只有两个连接，广播即精准路由）
//	server_AC  → Alice(connAC) + Catherine（只有两个连接，广播即精准路由）
//
// Alice 使用两个 Conn 对象并发运行，分别代表她与 Bob 和与 Catherine 的会话。
// 两组会话完全并发，互不干扰。
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
	newConn := func(wsURL, hostId string) *Conn {
		ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
		if err != nil {
			t.Fatalf("[%s] Dial(%s) failed: %v", hostId, wsURL, err)
		}
		conn, err := NewSecureConn(ws, hostId, &Config{
			KeyStorePath: keyStorePath,
			Compressor:   mockComp,
			Encoder:      encoder.NewGobEncoder(),
		})
		if err != nil {
			t.Fatalf("[%s] NewSecureConn failed: %v", hostId, err)
		}
		return conn
	}

	// 3. 启动两台专属 mock server
	// ── Server AB：只有 Alice 和 Bob ──────────────────────────────────────
	srvAB := httptest.NewServer(http.HandlerFunc(newMockServer().handler))
	defer srvAB.Close()
	urlAB := "ws" + strings.TrimPrefix(srvAB.URL, "http")

	// ── Server AC：只有 Alice 和 Catherine ────────────────────────────────
	srvAC := httptest.NewServer(http.HandlerFunc(newMockServer().handler))
	defer srvAC.Close()
	urlAC := "ws" + strings.TrimPrefix(srvAC.URL, "http")

	// 4. 各方连接
	connAliceAB := newConn(urlAB, "1111111111") // Alice 连接至 server_AB（与 Bob 通信）
	defer connAliceAB.Close()

	connBob := newConn(urlAB, "2222222222") // Bob 连接至 server_AB
	defer connBob.Close()

	connAliceAC := newConn(urlAC, "1111111111") // Alice 连接至 server_AC（与 Catherine 通信）
	defer connAliceAC.Close()

	connCatherine := newConn(urlAC, "3333333333") // Catherine 连接至 server_AC
	defer connCatherine.Close()

	// 等待 mock server 注册完所有连接
	time.Sleep(100 * time.Millisecond)

	const msgCount = 3

	// decodeMsg 解析收到的原始字节并返回文本内容
	decodeMsg := func(raw []byte) (string, bool) {
		var req Req
		if err := encoder.NewGobEncoder().Decode(raw, &req); err != nil {
			return "", false
		}
		var md sdkws.MsgData
		if err := proto.Unmarshal(req.Data, &md); err != nil {
			return "", false
		}
		return string(md.Content), true
	}

	var wg sync.WaitGroup

	// ── 会话 AB：Alice ↔ Bob ──────────────────────────────────────────────

	// Alice 向 Bob 发送 msgCount 条消息
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < msgCount; i++ {
			payload := makeAppMsg(t, "1111111111", "2222222222",
				[]byte(fmt.Sprintf("Alice to Bob #%d", i)))
			if err := connAliceAB.WriteMessage(websocket.BinaryMessage, payload); err != nil {
				t.Errorf("Alice(AB) → Bob write[%d] failed: %v", i, err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Bob 接收并回复
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

	// Alice 接收 Bob 的回复
	wg.Add(1)
	go func() {
		defer wg.Done()
		received := 0
		for received < msgCount {
			_, raw, err := connAliceAB.ReadMessage()
			if err != nil {
				t.Errorf("Alice(AB) ReadMessage failed: %v", err)
				return
			}
			text, ok := decodeMsg(raw)
			if !ok || !strings.Contains(text, "Bob reply") {
				continue
			}
			received++
			t.Logf("Alice ← Bob reply[%d]: %s", received, text)
		}
	}()

	// ── 会话 AC：Alice ↔ Catherine ────────────────────────────────────────

	// Alice 向 Catherine 发送 msgCount 条消息
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < msgCount; i++ {
			payload := makeAppMsg(t, "1111111111", "3333333333",
				[]byte(fmt.Sprintf("Alice to Catherine #%d", i)))
			if err := connAliceAC.WriteMessage(websocket.BinaryMessage, payload); err != nil {
				t.Errorf("Alice(AC) → Catherine write[%d] failed: %v", i, err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Catherine 接收并回复
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

	// Alice 接收 Catherine 的回复
	wg.Add(1)
	go func() {
		defer wg.Done()
		received := 0
		for received < msgCount {
			_, raw, err := connAliceAC.ReadMessage()
			if err != nil {
				t.Errorf("Alice(AC) ReadMessage failed: %v", err)
				return
			}
			text, ok := decodeMsg(raw)
			if !ok || !strings.Contains(text, "Catherine reply") {
				continue
			}
			received++
			t.Logf("Alice ← Catherine reply[%d]: %s", received, text)
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
		t.Log("TestE2E_MultiPeer PASSED - Alice ↔ Bob 和 Alice ↔ Catherine 并发通信均成功")
	case <-time.After(15 * time.Second):
		t.Fatal("TestE2E_MultiPeer timed out")
	}
}
