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
	openimmarshal "github.com/albert/ws_client/e2ewebsocket/im_parser/openim_marshal"
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
		// 根据消息协议：首字节(类型)
		if len(msg) < 1 {
			continue // 丢弃不合法消息
		}
		
		// == Transform Req to Resp for application data ==
		// 解码客户端发来的 Req
		var req Req
		enc := encoder.NewGobEncoder()
		payload := msg[1:]
		if err := enc.Decode(payload, &req); err == nil && len(req.Data) > 0 {
			// 能解码成 Req 的大概率是业务消息，转换为 Resp 发出
			var msgData sdkws.MsgData
			if err := proto.Unmarshal(req.Data, &msgData); err == nil {
				pushMsg := &sdkws.PushMessages{
					Msgs: map[string]*sdkws.PullMsgs{
						msgData.RecvID: {
							Msgs: []*sdkws.MsgData{&msgData},
						},
					},
				}
				pbBytes, _ := proto.Marshal(pushMsg)
				resp := Resp{
					ReqIdentifier: req.ReqIdentifier,
					MsgIncr:       req.MsgIncr,
					OperationID:   req.OperationID,
					Data:          pbBytes,
				}
				newPayload, _ := enc.Encode(resp)
				newMsg := make([]byte, 1+len(newPayload))
				newMsg[0] = msg[0]
				copy(newMsg[1:], newPayload)
				msg = newMsg
			}
		}
		s.mu.Lock()
		for _, targetConn := range s.conns {
			if targetConn != conn {
				targetConn.WriteMessage(mt, msg)
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

	// 4. 连接
	// 按照顺序连接，保证 conns 数组里面的顺序：[1111111111, 2222222222]
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

	// 等待 mock server 将两个连接都加入 conns 数组
	time.Sleep(100 * time.Millisecond)

	// 5. 并发读写测试
	var wg sync.WaitGroup
	wg.Add(2)

	// Alice (1111111111) 循环发送消息，只发送给 Bob
	go func() {
		for i := 0; i < 3; i++ {
			originalText := fmt.Sprintf("Hello 2222222222 %d", i)
			payload := makeAppMsg(t, "1111111111", "2222222222", []byte(originalText))

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
			fmt.Println("Bob waiting to read...")
			_, msg, err := connBob.ReadMessage()
			fmt.Println("Bob read", len(msg), err)
			if err != nil {
				return
			}

			var resp Resp
			dec := encoder.NewGobEncoder()
			if err := dec.Decode(msg, &resp); err != nil {
				t.Errorf("Bob decode msg to Resp failed: %v", err)
				return
			}
			var pushMsg sdkws.PushMessages
			if err := proto.Unmarshal(resp.Data, &pushMsg); err != nil {
				t.Errorf("Bob unmarshal PushMessages failed: %v", err)
				return
			}
			var msgData *sdkws.MsgData
			for _, pull := range pushMsg.Msgs {
				for _, m := range pull.Msgs {
					msgData = m
				}
			}
			if msgData == nil {
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

			if count == 3 {
				return
			}
		}
	}()

	// Alice 接收所有的回复
	go func() {
		defer wg.Done()
		count := 0
		for {
			fmt.Println("Alice waiting to read...")
			_, msg, err := connAlice.ReadMessage()
			fmt.Println("Alice read", len(msg), err)
			if err != nil {
				return
			}

			var resp Resp
			dec := encoder.NewGobEncoder()
			if err := dec.Decode(msg, &resp); err != nil {
				t.Errorf("Alice decode msg to Resp failed: %v", err)
				return
			}
			var pushMsg sdkws.PushMessages
			if err := proto.Unmarshal(resp.Data, &pushMsg); err != nil {
				t.Errorf("Alice unmarshal PushMessages failed: %v", err)
				return
			}
			var msgData *sdkws.MsgData
			for _, pull := range pushMsg.Msgs {
				for _, m := range pull.Msgs {
					msgData = m
				}
			}
			if msgData == nil {
				continue
			}

			text := string(msgData.Content)
			if !strings.Contains(text, "reply to") {
				t.Errorf("Alice received unexpected text: %s", text)
			}

			count++
			if count == 3 { // Bob * 3
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
