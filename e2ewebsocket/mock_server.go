package e2ewebsocket

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	"github.com/qs3c/e2e-secure-ws/crypto"
	"github.com/qs3c/e2e-secure-ws/encoder"
	"google.golang.org/protobuf/proto"
)

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
		_ = conn.Close()
	}()

	enc := encoder.NewGobEncoder()

	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			break
		}

		var req Req
		if err := enc.Decode(msg, &req); err != nil || len(req.Data) == 0 {
			continue
		}

		var msgData sdkws.MsgData
		if err := proto.Unmarshal(req.Data, &msgData); err != nil {
			fmt.Printf("MOCK SERVER UNMARSHAL ERR: %v\n", err)
			continue
		}

		pushMsg := &sdkws.PushMessages{
			Msgs: map[string]*sdkws.PullMsgs{
				msgData.RecvID: {
					Msgs: []*sdkws.MsgData{&msgData},
				},
			},
		}
		pbBytes, _ := proto.Marshal(pushMsg)
		resp := Resp{
			ReqIdentifier: 2001,
			MsgIncr:       req.MsgIncr,
			OperationID:   req.OperationID,
			Data:          pbBytes,
		}
		newMsg, err := enc.Encode(resp)
		if err != nil {
			fmt.Printf("MOCK SERVER ENCODE RESP ERR: %v\n", err)
			continue
		}

		s.mu.Lock()
		targetConn := s.conns[msgData.RecvID]
		s.mu.Unlock()
		if targetConn != nil {
			_ = targetConn.WriteMessage(mt, newMsg)
		}
	}
}

func (s *mockServer) injectRawToUID(uid string, msg []byte) bool {
	s.mu.Lock()
	conn := s.conns[uid]
	s.mu.Unlock()
	if conn == nil {
		return false
	}
	return conn.WriteMessage(websocket.BinaryMessage, msg) == nil
}

func setupKeyStore(t *testing.T, baseDir, id string) {
	dir := filepath.Join(baseDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	priv, err := crypto.GenerateECKey(crypto.SM2Curve)
	if err != nil {
		t.Fatal(err)
	}

	pemPriv, err := priv.MarshalPKCS8PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "private_key.pem"), pemPriv, 0o644); err != nil {
		t.Fatal(err)
	}

	pub := priv.Public()
	pemPub, err := pub.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "public_key.pem"), pemPub, 0o644); err != nil {
		t.Fatal(err)
	}
}

func makeAppMsg(t *testing.T, from, to string, content []byte) []byte {
	msgData := sdkws.MsgData{
		SendID:      from,
		RecvID:      to,
		Content:     content,
		SessionType: 1,
		MsgFrom:     100,
		ContentType: 101,
	}
	dataBytes, err := proto.Marshal(&msgData)
	if err != nil {
		t.Fatal(err)
	}

	req := Req{
		ReqIdentifier: 1003,
		SendID:        from,
		OperationID:   fmt.Sprintf("op-%s-%d", from, time.Now().UnixNano()),
		MsgIncr:       fmt.Sprintf("msg-%s-%d", from, time.Now().UnixNano()),
		Data:          dataBytes,
	}

	payload, err := encoder.NewGobEncoder().Encode(req)
	if err != nil {
		t.Fatal(err)
	}
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
