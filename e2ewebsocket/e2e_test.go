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

	"github.com/albert/ws_client/crypto"
	"github.com/albert/ws_client/encoder"
	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
)

// MsgData 的 Mock 结构，为了构建有效的 WriteMessage 输入
// 因为 conn.go L347 用了 encoder.Decode(..., &req)
// 然后 L355 proto.Unmarshal(req.Data, &msgData)
// type Req struct {
// 	ReqIdentifier int32  `protobuf:"varint,1,opt,name=reqIdentifier,proto3" json:"reqIdentifier,omitempty"`
// 	Token         string `protobuf:"bytes,2,opt,name=token,proto3" json:"token,omitempty"`
// 	SendID        string `protobuf:"bytes,3,opt,name=sendID,proto3" json:"sendID,omitempty"`
// 	OperationID   string `protobuf:"bytes,4,opt,name=operationID,proto3" json:"operationID,omitempty"`
// 	MsgIncr       int32  `protobuf:"varint,5,opt,name=msgIncr,proto3" json:"msgIncr,omitempty"`
// 	Data          []byte `protobuf:"bytes,6,opt,name=data,proto3" json:"data,omitempty"`
// }

// 模拟的 Relay Server
// 简单的广播服务器：收到消息后转发给除发送者以外的所有人
type mockServer struct {
	mu    sync.Mutex
	conns map[*websocket.Conn]string // conn -> id (if known)
}

func newMockServer() *mockServer {
	return &mockServer{
		conns: make(map[*websocket.Conn]string),
	}
}

func (s *mockServer) handler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	s.mu.Lock()
	s.conns[conn] = ""
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		// 广播
		s.mu.Lock()
		for c := range s.conns {
			if c != conn {
				c.WriteMessage(mt, msg)
			}
		}
		s.mu.Unlock()
	}
}

// 生成密钥对并保存到指定目录
func setupKeyStore(t *testing.T, baseDir, id string) {
	dir := filepath.Join(baseDir, id)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}

	// 生成 SM2 密钥
	priv, err := crypto.GenerateECKey(crypto.SM2Curve)
	if err != nil {
		t.Fatal(err)
	}

	// 保存私钥
	pemPriv, err := priv.MarshalPKCS8PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private_key.pem"), pemPriv, 0644); err != nil {
		t.Fatal(err)
	}

	// 保存公钥
	pub := priv.Public()
	pemPub, err := pub.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "public_key.pem"), pemPub, 0644); err != nil {
		t.Fatal(err)
	}
}

// 交换公钥：Mock "Key Distribution Center"
// 让 Alice 目录里有 Bob 的公钥，反之亦然
func exchangeKeys(t *testing.T, baseDir, idA, idB string) {
	// A <- B
	pubB, err := os.ReadFile(filepath.Join(baseDir, idB, "public_key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	// 放在 A 目录下的 B 子目录
	dirA_B := filepath.Join(baseDir, idA, idB)
	if err := os.MkdirAll(dirA_B, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirA_B, "public_key.pem"), pubB, 0644); err != nil {
		t.Fatal(err)
	}

	// B <- A
	pubA, err := os.ReadFile(filepath.Join(baseDir, idA, "public_key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	dirB_A := filepath.Join(baseDir, idB, idA)
	if err := os.MkdirAll(dirB_A, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dirB_A, "public_key.pem"), pubA, 0644); err != nil {
		t.Fatal(err)
	}
}

// 构造一个符合协议的应用层消息包
func makeAppMsg(t *testing.T, from, to string, content []byte) []byte {
	// 1. 构造 sdkws.MsgData (protobuf)
	msgData := sdkws.MsgData{
		SendID:      from,
		RecvID:      to,
		Content:     content,
		SessionType: 1, // SingleChat
		MsgFrom:     100,
		ContentType: 101,
	}
	dataBytes, err := proto.Marshal(&msgData)
	if err != nil {
		t.Fatal(err)
	}

	// 2. 构造 Req (gob 能够解码的结构，或者代码中使用的结构)
	// 注意代码中使用了 encoder.Decode(..., &req)
	// 而默认 encoder 是 Gob
	// 所以我们需要用 Gob 编码一个 Req 结构体，且 Req.Data = protobuf bytes
	req := Req{
		Data: dataBytes,
	}

	enc := encoder.NewGobEncoder()
	payload, err := enc.Encode(req)
	if err != nil {
		t.Fatal(err)
	}

	// 3. 压缩 (代码中先解压)
	// 默认使用 Gzip
	// 这里为了简单，如果代码允许不压缩最好，但代码 conn.go L340 ParseReceivedMsg 是强制 DecompressWithPool
	// 所以我们必须压缩
	// 这里的 compressor.Compressor 接口实现可能是 gzip
	// 由于没有直接引用 gzip 包，我们假设 Config 默认是 Gzip
	// 我们可以直接用 conn.config.Compressor 来压缩，或者 mock 一个

	// 为了测试方便，我们可以不压缩? 不行，conn.go:340 会报错
	// 我们需要在测试中配置一个 "NoOp" Compressor 或者使用真实的 Gzip
	return payload
}

func TestE2E_Concurrent(t *testing.T) {
	// 1. 环境准备
	// 使用已生成的静态密钥，位于 ../static_key
	cwd, _ := os.Getwd()
	keyStorePath := filepath.Join(filepath.Dir(cwd), "static_key")
	if _, err := os.Stat(keyStorePath); os.IsNotExist(err) {
		t.Skipf("static_key dir not found at %s", keyStorePath)
	}

	// setupKeyStore(t, tmpDir, "alice")
	// setupKeyStore(t, tmpDir, "bob")
	// exchangeKeys(t, tmpDir, "alice", "bob")

	// 2. 启动 Mock Server
	ms := newMockServer()
	s := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer s.Close()
	wsUrl := "ws" + strings.TrimPrefix(s.URL, "http")

	// 3. 配置 Config
	// 我们需要一个支持 Gzip 的 Compressor
	// 由于 albert/ws_client/compressor 包的可见性，我们直接使用默认 Gzip
	// 但这要求我们在测试代码里也能正确压缩。
	// 这里稍微偷懒：我们在 Config 里注入一个 Mock Compressor，它是透传的，不压缩
	mockComp := &MockCompressor{}

	cfgAlice := &Config{
		KeyStorePath: keyStorePath,
		Compressor:   mockComp,
		Encoder:      encoder.NewGobEncoder(),
	}
	cfgBob := &Config{
		KeyStorePath: keyStorePath,
		Compressor:   mockComp,
		Encoder:      encoder.NewGobEncoder(),
	}

	// 4. 连接
	// Alice
	wsAlice, _, err := websocket.DefaultDialer.Dial(wsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	connAlice := NewSecureConn(wsAlice, "alice", cfgAlice)
	defer connAlice.Close()

	// Bob
	wsBob, _, err := websocket.DefaultDialer.Dial(wsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	connBob := NewSecureConn(wsBob, "bob", cfgBob)
	defer connBob.Close()

	// 5. 并发读写测试
	var wg sync.WaitGroup
	wg.Add(2)

	// Alice 循环发送消息给 Bob
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			originalText := fmt.Sprintf("Hello Bob %d", i)
			payload := makeAppMsg(t, "alice", "bob", []byte(originalText))

			// 并发写
			go func() {
				// 模拟上层应用的其他并发行为（如果有）
				// 但这里主要是主循环发
			}()

			err := connAlice.WriteMessage(websocket.BinaryMessage, payload)
			if err != nil {
				t.Errorf("Alice write failed: %v", err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Bob 循环读取消息
	go func() {
		defer wg.Done()
		count := 0
		for {
			_, msg, err := connBob.ReadMessage()
			if err != nil {
				// 连接关闭或错误
				return
			}
			// 解码验证
			// Conn 返回的是解密后的 [Req] 的 [MsgData] 吗?
			// 不，conn.go:185 返回的是 data (session.in.decrypt 解密后的)
			// 这个 data 对应的是 WriteMessage 时传入的 payload (即 makeAppMsg 的结果)
			// 所以 Bob 读到的是 [Compressed [Gob [Req [Proto [MsgData]]]]]

			// Mock Compressor 是透传
			// Gob Decode
			var req Req
			dec := encoder.NewGobEncoder()
			if err := dec.Decode(msg, &req); err != nil {
				t.Errorf("Bob deccode req failed: %v", err)
				continue
			}
			var msgData sdkws.MsgData
			if err := proto.Unmarshal(req.Data, &msgData); err != nil {
				t.Errorf("Bob unmarshal proto failed: %v", err)
				continue
			}

			text := string(msgData.Content)
			if !strings.Contains(text, "Hello Bob") {
				t.Errorf("Bob received unexpected text: %s", text)
			}
			// fmt.Printf("Bob received: %s\n", text)
			count++
			if count == 10 {
				return
			}
		}
	}()

	// 同时 Alice 也可以读 (Wait for Bob response if we implemented Echo)
	// Make connection full duplex
	go func() {
		for {
			_, _, err := connAlice.ReadMessage()
			if err != nil {
				t.Logf("Alice ReadMessage error: %v", err)
				return
			}
		}
	}()

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out")
	}
}

type MockCompressor struct{}

func (m *MockCompressor) Compress(data []byte) ([]byte, error) {
	return data, nil
}
func (m *MockCompressor) DeCompress(data []byte) ([]byte, error) {
	return data, nil
}
func (m *MockCompressor) CompressWithPool(data []byte) ([]byte, error) {
	return data, nil
}
func (m *MockCompressor) DecompressWithPool(data []byte) ([]byte, error) {
	return data, nil
}
