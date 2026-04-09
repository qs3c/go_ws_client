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

	"github.com/qs3c/e2e-secure-ws/encoder"
	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
	openimmarshal "github.com/qs3c/e2e-secure-ws/e2ewebsocket/im_parser/openim_marshal"
)

// TestE2E_ConcurrentHandshake 测试双端几乎同时发送首条消息时触发的并发握手碰撞场景。
// 核心验证点：
//  1. Alice 和 Bob 在互不知情的情况下几乎同时向对方发出第一条业务消息。
//  2. 两端的底层加密连接层应当能自动协商并完成密钥交换（无论谁先谁后）。
//  3. 双方最终都应该能成功收到对方发出的那条消息，内容完整且正确。
//  4. 不应发生死锁、panic 或报错。
func TestE2E_ConcurrentHandshake(t *testing.T) {
	cwd, _ := os.Getwd()
	keyStorePath := filepath.Join(filepath.Dir(cwd), "static_key")
	if _, err := os.Stat(keyStorePath); os.IsNotExist(err) {
		t.Skipf("static_key 不存在于 %s", keyStorePath)
	}

	// 1. 启动 Mock Server
	ms := newMockServer()
	s := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer s.Close()
	wsUrl := "ws" + strings.TrimPrefix(s.URL, "http")

	// 2. 建立连接辅助函数（与其他测试风格一致）
	mockComp := &MockCompressor{}
	parser := openimmarshal.NewOpenIMParser(encoder.NewGobEncoder(), mockComp)
	newConn := func(wsURL, hostId string) *Conn {
		conn, err := NewSecureConn(&Config{
			KeyStorePath: keyStorePath,
			Compressor:   mockComp,
			Encoder:      encoder.NewGobEncoder(),
		}, parser)
		if err != nil {
			t.Fatalf("[%s] NewSecureConn failed: %v", hostId, err)
		}
		_, err = conn.DialAndSetUserId(wsURL+"?uid="+hostId, hostId, nil)
		if err != nil {
			t.Fatalf("[%s] Dial failed: %v", hostId, err)
		}
		return conn
	}

	connAlice := newConn(wsUrl, "1111111111")
	defer connAlice.Close()

	connBob := newConn(wsUrl, "2222222222")
	defer connBob.Close()

	// 等待 mock server 注册两个连接
	time.Sleep(50 * time.Millisecond)

	// 解码辅助函数
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

	// 3. 核心：使用 sync.WaitGroup + 屏障（barrier）让 Alice 和 Bob 尽量同时发出第一条消息
	//    这样两端都会在对方的 session 尚未建立时就收到了消息，触发被动握手。
	errCh := make(chan error, 4)
	var barrier sync.WaitGroup
	barrier.Add(2)

	aliceRecvCh := make(chan string, 1)
	bobRecvCh := make(chan string, 1)

	// Alice：准备就绪后立刻发送，然后等待 Bob 的回包
	go func() {
		barrier.Done()
		barrier.Wait() // 等待 Bob 也准备好，然后同时冲
		t.Log("Alice: 发送第一条消息（主动触发握手）...")
		payload := makeAppMsg(t, "1111111111", "2222222222", []byte("Alice's first message"))
		start := time.Now()
		if err := connAlice.WriteMessage(websocket.BinaryMessage, payload); err != nil {
			errCh <- fmt.Errorf("Alice WriteMessage failed: %v", err)
			return
		}
		t.Logf("Alice: WriteMessage 完成（含握手耗时 %v），等待 Bob 回包...", time.Since(start))
		_, msg, err := connAlice.ReadMessage()
		if err != nil {
			errCh <- fmt.Errorf("Alice ReadMessage failed: %v", err)
			return
		}
		text, ok := decodeMsg(msg)
		if !ok {
			errCh <- fmt.Errorf("Alice decoded empty/invalid reply")
			return
		}
		aliceRecvCh <- text
		errCh <- nil
	}()

	// Bob：准备就绪后立刻发送，然后等待 Alice 的回包
	go func() {
		barrier.Done()
		barrier.Wait() // 与 Alice 同步冲
		t.Log("Bob: 发送第一条消息（主动触发握手）...")
		payload := makeAppMsg(t, "2222222222", "1111111111", []byte("Bob's first message"))
		start := time.Now()
		if err := connBob.WriteMessage(websocket.BinaryMessage, payload); err != nil {
			errCh <- fmt.Errorf("Bob WriteMessage failed: %v", err)
			return
		}
		t.Logf("Bob: WriteMessage 完成（含握手耗时 %v），等待 Alice 回包...", time.Since(start))
		_, msg, err := connBob.ReadMessage()
		if err != nil {
			errCh <- fmt.Errorf("Bob ReadMessage failed: %v", err)
			return
		}
		text, ok := decodeMsg(msg)
		if !ok {
			errCh <- fmt.Errorf("Bob decoded empty/invalid reply")
			return
		}
		bobRecvCh <- text
		errCh <- nil
	}()

	// 4. 等待两个协程告知结果，超时兜底
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()

	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatal(err)
			}
		case <-timer.C:
			t.Fatal("TestE2E_ConcurrentHandshake timed out")
		}
	}

	// 5. 断言消息内容正确
	aliceGot := <-aliceRecvCh
	bobGot := <-bobRecvCh

	if bobGot != "Alice's first message" {
		t.Fatalf("Bob 收到的内容不符：got %q, want %q", bobGot, "Alice's first message")
	}
	if aliceGot != "Bob's first message" {
		t.Fatalf("Alice 收到的内容不符：got %q, want %q", aliceGot, "Bob's first message")
	}
	t.Logf("Bob 收到了: %q", bobGot)
	t.Logf("Alice 收到了: %q", aliceGot)
	t.Log("TestE2E_ConcurrentHandshake PASSED - 双端并发首条消息测试通过，无死锁，无丢包！")
}
