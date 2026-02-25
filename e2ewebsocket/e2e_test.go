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
// 根据要求：收到 conns[0] 的消息交替转发给 conns[1] 和 conns[2]
// conns[1] 和 conns[2] 收到的消息转发给 conns[0]
type mockServer struct {
	mu    sync.Mutex
	conns []*websocket.Conn
	turn  int
}

func newMockServer() *mockServer {
	return &mockServer{
		conns: make([]*websocket.Conn, 0),
	}
}

func (s *mockServer) handler(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	s.mu.Lock()
	s.conns = append(s.conns, conn)
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		for i, c := range s.conns {
			if c == conn {
				s.conns = append(s.conns[:i], s.conns[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
		conn.Close()
	}()

	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}
		// 路由转发
		s.mu.Lock()
		if len(s.conns) >= 3 {
			if conn == s.conns[0] {
				if s.turn == 0 {
					s.conns[1].WriteMessage(mt, msg)
					s.turn = 1
				} else {
					s.conns[2].WriteMessage(mt, msg)
					s.turn = 0
				}
			} else if conn == s.conns[1] || conn == s.conns[2] {
				s.conns[0].WriteMessage(mt, msg)
			}
		} else {
			fmt.Printf("mockServer 报错: 预期至少有 3 个连接，当前只有 %d 个\n", len(s.conns))
			s.mu.Unlock()
			break
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
	// 假设密钥已经在之前的步骤中生成好并保存在 ../static_key 目录下
	cwd, _ := os.Getwd()
	keyStorePath := filepath.Join(filepath.Dir(cwd), "static_key")
	if _, err := os.Stat(keyStorePath); os.IsNotExist(err) {
		t.Skipf("static_key 目录不存在于 %s, 请先运行 TestGenerateStaticKeys 生成密钥", keyStorePath)
	}

	// 2. 启动 Mock Server
	ms := newMockServer()
	s := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer s.Close()
	wsUrl := "ws" + strings.TrimPrefix(s.URL, "http")

	// 3. 配置 Config
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
	cfgCharlie := &Config{
		KeyStorePath: keyStorePath,
		Compressor:   mockComp,
		Encoder:      encoder.NewGobEncoder(),
	}

	// 4. 连接
	// 按照顺序连接，保证 conns 数组里面的顺序：[1111111111, 2222222222, 3333333333]
	wsAlice, _, err := websocket.DefaultDialer.Dial(wsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	connAlice, err := NewSecureConn(wsAlice, "1111111111", cfgAlice)
	if err != nil {
		t.Fatal(err)
	}
	defer connAlice.Close()

	wsBob, _, err := websocket.DefaultDialer.Dial(wsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	connBob, err := NewSecureConn(wsBob, "2222222222", cfgBob)
	if err != nil {
		t.Fatal(err)
	}
	defer connBob.Close()

	wsCharlie, _, err := websocket.DefaultDialer.Dial(wsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	connCharlie, err := NewSecureConn(wsCharlie, "3333333333", cfgCharlie)
	if err != nil {
		t.Fatal(err)
	}
	defer connCharlie.Close()

	// 等待 mock server 将三个连接都加入 conns 数组
	time.Sleep(100 * time.Millisecond)

	// 5. 并发读写测试
	var wg sync.WaitGroup
	wg.Add(3)

	// Alice (1111111111) 循环发送消息，按照要求交替发给 Bob 和 Charlie
	go func() {
		for i := 0; i < 10; i++ {
			to := "2222222222"
			if i%2 != 0 {
				to = "3333333333"
			}
			originalText := fmt.Sprintf("Hello %s %d", to, i)
			payload := makeAppMsg(t, "1111111111", to, []byte(originalText))

			err := connAlice.WriteMessage(websocket.BinaryMessage, payload)
			if err != nil {
				t.Errorf("Alice write failed: %v", err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	// Bob 循环读取消息并回复
	go func() {
		defer wg.Done()
		count := 0
		for {
			_, msg, err := connBob.ReadMessage()
			if err != nil {
				return
			}

			var req Req
			dec := encoder.NewGobEncoder()
			if err := dec.Decode(msg, &req); err != nil {
				continue
			}
			var msgData sdkws.MsgData
			if err := proto.Unmarshal(req.Data, &msgData); err != nil {
				continue
			}

			text := string(msgData.Content)
			if !strings.Contains(text, "Hello 2222222222") {
				t.Errorf("Bob received unexpected text: %s", text)
			}

			count++
			// 回复 Alice
			replyText := fmt.Sprintf("2222222222 reply to %s", text)
			replyPayload := makeAppMsg(t, "2222222222", "1111111111", []byte(replyText))
			connBob.WriteMessage(websocket.BinaryMessage, replyPayload)

			if count == 5 {
				return
			}
		}
	}()

	// Charlie 循环读取消息并回复
	go func() {
		defer wg.Done()
		count := 0
		for {
			_, msg, err := connCharlie.ReadMessage()
			if err != nil {
				return
			}

			var req Req
			dec := encoder.NewGobEncoder()
			if err := dec.Decode(msg, &req); err != nil {
				continue
			}
			var msgData sdkws.MsgData
			if err := proto.Unmarshal(req.Data, &msgData); err != nil {
				continue
			}

			text := string(msgData.Content)
			if !strings.Contains(text, "Hello 3333333333") {
				t.Errorf("Charlie received unexpected text: %s", text)
			}

			count++
			// 回复 Alice
			replyText := fmt.Sprintf("Charlie reply to %s", text)
			replyPayload := makeAppMsg(t, "3333333333", "1111111111", []byte(replyText))
			connCharlie.WriteMessage(websocket.BinaryMessage, replyPayload)

			if count == 5 {
				return
			}
		}
	}()

	// Alice 接收所有的回复
	go func() {
		defer wg.Done()
		count := 0
		for {
			_, msg, err := connAlice.ReadMessage()
			if err != nil {
				return
			}

			var req Req
			dec := encoder.NewGobEncoder()
			if err := dec.Decode(msg, &req); err != nil {
				continue
			}
			var msgData sdkws.MsgData
			if err := proto.Unmarshal(req.Data, &msgData); err != nil {
				continue
			}

			text := string(msgData.Content)
			if !strings.Contains(text, "reply to") {
				t.Errorf("Alice received unexpected text: %s", text)
			}

			count++
			if count == 10 { // Bob * 5 + Charlie * 5
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
	case <-time.After(10 * time.Second):
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
