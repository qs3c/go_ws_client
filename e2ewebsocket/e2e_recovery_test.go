package e2ewebsocket

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qs3c/e2e-secure-ws/encoder"
	openimmarshal "github.com/qs3c/e2e-secure-ws/e2ewebsocket/im_parser/openim_marshal"
	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
)

// ===========================================================
// 辅助：解码收到的消息并返回 Content 字符串
// ===========================================================
func decodeMsgContent(raw []byte) (string, bool) {
	var resp Resp
	if err := encoder.NewGobEncoder().Decode(raw, &resp); err != nil {
		return "", false
	}
	var pushMsg sdkws.PushMessages
	if err := proto.Unmarshal(resp.Data, &pushMsg); err != nil {
		return "", false
	}
	for _, pull := range pushMsg.Msgs {
		for _, m := range pull.Msgs {
			return string(m.Content), true
		}
	}
	return "", false
}

// ===========================================================
// 辅助：等待 Alice 的 sessions map 中指定 sessionId 被删除
// ===========================================================
func waitSessionDeleted(conn *Conn, sessionId SessionID, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, ok := conn.sessions.Load(sessionId); !ok {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// ===========================================================
// 测试套件启动辅助
// ===========================================================
func setupRecoveryTest(t *testing.T) (ms *mockServer, wsUrl string, keyStorePath string, newConn func(string) *Conn) {
	t.Helper()
	cwd, _ := os.Getwd()
	keyStorePath = filepath.Join(filepath.Dir(cwd), "static_key")
	if _, err := os.Stat(keyStorePath); os.IsNotExist(err) {
		t.Skipf("static_key 不存在于 %s", keyStorePath)
	}

	ms = newMockServer()
	srv := httptest.NewServer(http.HandlerFunc(ms.handler))
	t.Cleanup(srv.Close)
	wsUrl = "ws" + strings.TrimPrefix(srv.URL, "http")

	mockComp := &MockCompressor{}
	parser := openimmarshal.NewOpenIMParser(encoder.NewGobEncoder(), mockComp)

	newConn = func(hostId string) *Conn {
		conn, err := NewSecureConn(hostId, &Config{
			KeyStorePath: keyStorePath,
			Compressor:   mockComp,
			Encoder:      encoder.NewGobEncoder(),
		}, parser)
		if err != nil {
			t.Fatalf("[%s] NewSecureConn failed: %v", hostId, err)
		}
		_, err = conn.Dial(wsUrl+"?uid="+hostId, nil)
		if err != nil {
			t.Fatalf("[%s] Dial failed: %v", hostId, err)
		}
		return conn
	}
	return
}

// ============================================================
// TestE2E_Recovery_ForceTerminateAndRebuild
// 用例一：主动调用 terminateSession 强制销毁 Alice-Bob session
//
// 流程：
//  1. Alice → Bob 发消息1，握手完成，正常收到。
//  2. 测试代码直接调用 connAlice.terminateSession(session, err)
//     → Alice 删除本地 session，并通过真实 WebSocket 向 Bob 发 Alert
//     → Bob 的 readLoop 收到 Alert，调用 closeSessionLocally 删除 Bob 侧 session
//  3. Alice → Bob 发消息2（WriteMessage 中 session=nil → 惰性重建 → 重新握手）
//  4. Bob 收到消息2，内容正确。
//
// 验收：无 panic/死锁，消息2 内容正确。
// ============================================================
func TestE2E_Recovery_ForceTerminateAndRebuild(t *testing.T) {
	_, _, _, newConn := setupRecoveryTest(t)

	connAlice := newConn("1111111111")
	defer connAlice.Close()
	connBob := newConn("2222222222")
	defer connBob.Close()

	// 等待 mock server 注册连接
	time.Sleep(100 * time.Millisecond)

	// ── 步骤1：正常发送消息1，确认握手完成 ──────────────────────────────────
	payload1 := makeAppMsg(t, "1111111111", "2222222222", []byte("before-recovery-msg"))
	if err := connAlice.WriteMessage(websocket.BinaryMessage, payload1); err != nil {
		t.Fatalf("步骤1 Alice WriteMessage 失败: %v", err)
	}
	_, raw1, err := connBob.ReadMessage()
	if err != nil {
		t.Fatalf("步骤1 Bob ReadMessage 失败: %v", err)
	}
	text1, ok := decodeMsgContent(raw1)
	if !ok || text1 != "before-recovery-msg" {
		t.Fatalf("步骤1 Bob 收到内容错误: got %q", text1)
	}
	t.Logf("步骤1 PASS：正常握手通信成功，Bob 收到 %q", text1)

	// ── 步骤2：强制销毁 Alice 侧 session ─────────────────────────────────────
	// 从 Alice 的 sessions map 取出对应 session
	aliceBobSessionId := getSessionID("1111111111", "2222222222")
	val, loaded := connAlice.sessions.Load(aliceBobSessionId)
	if !loaded {
		t.Fatalf("步骤2：找不到 Alice-Bob session（id=%s）", aliceBobSessionId)
	}
	aliceSession := val.(*Session)

	// terminateSession 会：
	//   a) 向 Bob 发送 Alert（经过真实 WebSocket）
	//   b) 关闭 Alice 侧的 session 并从 map 删除
	t.Log("步骤2：强制调用 terminateSession，销毁 Alice-Bob session...")
	connAlice.terminateSession(aliceSession, errors.New("test: forced termination"))

	// 验证 Alice 侧 session 已删除
	if _, stillExists := connAlice.sessions.Load(aliceBobSessionId); stillExists {
		t.Fatal("步骤2：Alice 侧 session 未被删除")
	}
	t.Log("步骤2 PASS：Alice 侧 session 已删除，Alert 已发出")

	// 给 Bob 的 readLoop 一点时间处理 Alert 并 closeSessionLocally
	if !waitSessionDeleted(connBob, aliceBobSessionId, 2*time.Second) {
		t.Fatal("步骤2：等待 Bob 侧 session 被删除超时")
	}
	t.Log("步骤2 PASS：Bob 侧 session 也已删除（Alert 生效）")

	// ── 步骤3&4：Alice 重新发送消息2，期望惰性重建 session 后成功 ────────────
	errCh := make(chan error, 2)

	// Alice 发消息2
	go func() {
		payload2 := makeAppMsg(t, "1111111111", "2222222222", []byte("after-recovery-msg"))
		t.Log("步骤3：Alice 开始发送消息2（预期触发惰性 session 重建）...")
		start := time.Now()
		if err := connAlice.WriteMessage(websocket.BinaryMessage, payload2); err != nil {
			errCh <- fmt.Errorf("步骤3 Alice WriteMessage 失败: %v", err)
			return
		}
		t.Logf("步骤3 PASS：Alice WriteMessage 成功（含重握手耗时 %v）", time.Since(start))
		errCh <- nil
	}()

	// Bob 收消息2
	go func() {
		_, raw2, err := connBob.ReadMessage()
		if err != nil {
			errCh <- fmt.Errorf("步骤4 Bob ReadMessage 失败: %v", err)
			return
		}
		text2, ok := decodeMsgContent(raw2)
		if !ok || text2 != "after-recovery-msg" {
			errCh <- fmt.Errorf("步骤4 Bob 收到内容错误: got %q, want %q", text2, "after-recovery-msg")
			return
		}
		t.Logf("步骤4 PASS：Bob 收到恢复后的消息 %q", text2)
		errCh <- nil
	}()

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatal(err)
			}
		case <-timer.C:
			t.Fatal("TestE2E_Recovery_ForceTerminateAndRebuild 超时")
		}
	}
	t.Log("TestE2E_Recovery_ForceTerminateAndRebuild PASSED")
}

// ============================================================
// TestE2E_Recovery_DecryptFailTriggersRebuild
// 用例二：解密失败触发 session 终止与重建
//
// 流程：
//  1. Alice → Bob 发消息1，确认握手完成（session 已加密）。
//  2. Mock server 向 Alice 注入一条格式合法但 Content 字段是随机乱码的
//     ApplicationData 帧（以 Bob 的身份发送）。
//  3. Alice 的 readLoop 解析 sessionId 成功，但 session.in.decrypt 失败，
//     触发 terminateSession → 向 Bob 发 Alert → Bob closeSessionLocally。
//  4. Alice → Bob 发消息2，WriteMessage 检测 session=nil，惰性重建，握手成功。
//  5. Bob 收到消息2，内容正确。
//
// 验收：无 panic/死锁，消息2 内容正确。
// ============================================================
func TestE2E_Recovery_DecryptFailTriggersRebuild(t *testing.T) {
	ms, _, _, newConn := setupRecoveryTest(t)

	connAlice := newConn("1111111111")
	defer connAlice.Close()
	connBob := newConn("2222222222")
	defer connBob.Close()

	time.Sleep(100 * time.Millisecond)

	// ── 步骤1：正常通信，确认握手完成 ────────────────────────────────────────
	payload1 := makeAppMsg(t, "1111111111", "2222222222", []byte("normal-msg"))
	if err := connAlice.WriteMessage(websocket.BinaryMessage, payload1); err != nil {
		t.Fatalf("步骤1 Alice WriteMessage 失败: %v", err)
	}
	_, raw1, err := connBob.ReadMessage()
	if err != nil {
		t.Fatalf("步骤1 Bob ReadMessage 失败: %v", err)
	}
	if text1, ok := decodeMsgContent(raw1); !ok || text1 != "normal-msg" {
		t.Fatalf("步骤1 Bob 收到内容错误: %q", text1)
	}
	t.Log("步骤1 PASS：正常握手通信成功")

	// ── 步骤2：注入乱码前，先断言 cipher 已激活（AEAD，非 nil）─────────────
	// 这是本测试的前提：session.in.cipher 必须已设置（握手完成后 changeCipherSpec 切换），
	// 否则 decrypt 会执行 plaintext=payload 分支直接放行，不会触发 terminateSession。
	aliceBobSessionId := getSessionID("1111111111", "2222222222")
	val, loaded := connAlice.sessions.Load(aliceBobSessionId)
	if !loaded {
		t.Fatal("步骤2前置断言：Alice-Bob session 不存在，握手可能未完成")
	}
	aliceSession := val.(*Session)
	aliceSession.in.Lock()
	cipherIsSet := aliceSession.in.cipher != nil
	aliceSession.in.Unlock()
	if !cipherIsSet {
		t.Fatal("步骤2前置断言：session.in.cipher 为 nil，表示 AEAD 尚未激活，注入乱码不会触发 decrypt 失败")
	}
	t.Log("步骤2 前置断言 PASS：session.in.cipher 已激活（AEAD），乱码内容必然触发 decrypt 失败")

	// ── 步骤2：构造并注入乱码 ApplicationData 给 Alice ───────────────────────
	// 构造 ReadBound 格式的消息（模拟服务器发给 Alice），sender=Bob
	// Content 字段填入随机乱码（无法被已建立的 session 解密）
	mockComp := &MockCompressor{}
	parser := openimmarshal.NewOpenIMParser(encoder.NewGobEncoder(), mockComp)
	// 构造 MsgData，sender=Bob(2222222222), receiver=Alice(1111111111), content=random junk
	corruptedContent := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	fakeMsgData := parser.ConstructMsgData("2222222222", "1111111111", corruptedContent)

	// 序列化为 ReadBound 格式字节（模拟 server → client 方向）
	msgDataBytes, err := parser.MsgDataToBytesReadBound(fakeMsgData)
	if err != nil {
		t.Fatalf("步骤2：MsgDataToBytesReadBound 失败: %v", err)
	}

	// 拼接帧头（1字节 recordTypeApplicationData）
	corruptedFrame := make([]byte, 1+len(msgDataBytes))
	corruptedFrame[0] = byte(recordTypeApplicationData)
	copy(corruptedFrame[1:], msgDataBytes)

	t.Log("步骤2：向 Alice 注入乱码 ApplicationData 帧（sender=Bob）...")
	if ok := ms.injectRawToUID("1111111111", corruptedFrame); !ok {
		t.Fatal("步骤2：injectRawToUID 失败（uid 未注册到 mock server）")
	}
	t.Log("步骤2 PASS：乱码帧注入成功")

	// ── 步骤3：等待 Alice 的 session 被 terminateSession 删除 ─────────────────
	if !waitSessionDeleted(connAlice, aliceBobSessionId, 3*time.Second) {
		t.Fatal("步骤3：等待 Alice 侧 session 因 decrypt 失败被删除超时")
	}
	t.Log("步骤3 PASS：Alice 侧 session 已因解密失败被终止，Alert 已发出")

	// 给 Bob 的 readLoop 一点时间处理 Alert
	if !waitSessionDeleted(connBob, aliceBobSessionId, 2*time.Second) {
		t.Fatal("步骤3：等待 Bob 侧 session 被删除（因 Alert）超时")
	}
	t.Log("步骤3 PASS：Bob 侧 session 也已删除（Alert 生效）")

	// ── 步骤4&5：Recovery - Alice 重发消息，期望惰性重建后正常 ───────────────
	errCh := make(chan error, 2)

	go func() {
		payload2 := makeAppMsg(t, "1111111111", "2222222222", []byte("recovery-msg"))
		t.Log("步骤4：Alice 开始发送恢复消息（预期惰性重建 session）...")
		start := time.Now()
		if err := connAlice.WriteMessage(websocket.BinaryMessage, payload2); err != nil {
			errCh <- fmt.Errorf("步骤4 Alice WriteMessage 失败: %v", err)
			return
		}
		t.Logf("步骤4 PASS：Alice WriteMessage 成功（含重握手耗时 %v）", time.Since(start))
		errCh <- nil
	}()

	go func() {
		_, raw2, err := connBob.ReadMessage()
		if err != nil {
			errCh <- fmt.Errorf("步骤5 Bob ReadMessage 失败: %v", err)
			return
		}
		text2, ok := decodeMsgContent(raw2)
		if !ok || text2 != "recovery-msg" {
			errCh <- fmt.Errorf("步骤5 Bob 收到内容错误: got %q, want %q", text2, "recovery-msg")
			return
		}
		t.Logf("步骤5 PASS：Bob 收到恢复后消息 %q", text2)
		errCh <- nil
	}()

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for i := 0; i < 2; i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatal(err)
			}
		case <-timer.C:
			t.Fatal("TestE2E_Recovery_DecryptFailTriggersRebuild 超时")
		}
	}
	t.Log("TestE2E_Recovery_DecryptFailTriggersRebuild PASSED")
}
