package e2ewebsocket

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/qs3c/e2e-secure-ws/crypto"
	"github.com/qs3c/e2e-secure-ws/encoder"
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
	conns map[string]*websocket.Conn
}

func newMockServer() *mockServer {
	return &mockServer{
		conns: make(map[string]*websocket.Conn),
	}
}

func (s *mockServer) handler(w http.ResponseWriter, r *http.Request) {
	// uid = hostId
	uid := r.URL.Query().Get("uid")
	upgrader := websocket.Upgrader{}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	if uid != "" {
		s.mu.Lock()
		s.conns[uid] = conn
		s.mu.Unlock()
	}

	defer func() {
		if uid != "" {
			s.mu.Lock()
			delete(s.conns, uid)
			s.mu.Unlock()
		}
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

				// 精准投递（附带并发写保护，防止 gorilla/websocket 崩溃）
				s.mu.Lock()
				targetConn := s.conns[msgData.RecvID]
				if targetConn != nil {
					targetConn.WriteMessage(mt, msg)
				}
				s.mu.Unlock()
			} else {
				fmt.Printf("MOCK SERVER UNMARSHAL ERR: %v\n", err)
			}
		} else {
			fmt.Printf("MOCK SERVER DECODE REQ ERR: %v\n", err)
		}
	}
}

// injectRawToUID 直接向指定 uid 的 ws 连接写入原始二进制帧，用于测试注入
func (s *mockServer) injectRawToUID(uid string, msg []byte) bool {
	s.mu.Lock()
	conn := s.conns[uid]
	s.mu.Unlock()
	if conn == nil {
		return false
	}
	return conn.WriteMessage(websocket.BinaryMessage, msg) == nil
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
