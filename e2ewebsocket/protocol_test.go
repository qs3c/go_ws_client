package e2ewebsocket

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/albert/ws_client/compressor"
	ccrypto "github.com/albert/ws_client/crypto"
	"github.com/albert/ws_client/encoder"
	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
)

func TestProtocolHandshakeAndMessageExchange(t *testing.T) {
	keystore := t.TempDir()
	clientID := "clientA"
	serverID := "serverB"

	if err := writeSM2KeyPair(keystore, clientID); err != nil {
		t.Fatalf("write client keys: %v", err)
	}
	if err := writeSM2KeyPair(keystore, serverID); err != nil {
		t.Fatalf("write server keys: %v", err)
	}

	cfgClient := &Config{KeyStorePath: keystore}
	cfgServer := &Config{KeyStorePath: keystore}

	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	serverConnCh := make(chan *Conn, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("upgrade failed: %v", err)
			return
		}
		serverConnCh <- NewSecureConn(ws, serverID, cfgServer)
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	clientWS, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}
	defer clientWS.Close()

	clientConn := NewSecureConn(clientWS, clientID, cfgClient)
	serverConn := <-serverConnCh
	defer serverConn.Close()

	msgToServer := buildWireMessage(t, cfgClient, serverID, "ping")
	msgToClient := buildWireMessage(t, cfgServer, clientID, "pong")

	srvDone := make(chan error, 1)
	go func() {
		_, data, err := serverConn.ReadMessage()
		if err != nil {
			srvDone <- fmt.Errorf("server read: %w", err)
			return
		}
		if !bytes.Equal(data, msgToServer) {
			srvDone <- fmt.Errorf("server received unexpected payload")
			return
		}
		srvDone <- serverConn.WriteMessage(websocket.BinaryMessage, msgToClient)
	}()

	if err := clientConn.WriteMessage(websocket.BinaryMessage, msgToServer); err != nil {
		t.Fatalf("client write: %v", err)
	}

	_, data, err := clientConn.ReadMessage()
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if !bytes.Equal(data, msgToClient) {
		t.Fatalf("client received unexpected payload")
	}

	select {
	case err := <-srvDone:
		if err != nil {
			t.Fatalf("server goroutine: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("timeout waiting for server")
	}
}

func buildWireMessage(t *testing.T, cfg *Config, recvID, content string) []byte {
	msg := &sdkws.MsgData{
		RecvID:  recvID,
		Content: []byte(content),
	}
	data, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal msgdata: %v", err)
	}

	req := Req{
		ReqIdentifier: 1,
		SendID:        "tester",
		OperationID:   "op",
		MsgIncr:       "1",
		Data:          data,
	}

	enc := cfg.encoder()
	encoded, err := enc.Encode(req)
	if err != nil {
		t.Fatalf("encode req: %v", err)
	}

	comp := cfg.compressor()
	compressed, err := comp.CompressWithPool(encoded)
	if err != nil {
		t.Fatalf("compress req: %v", err)
	}
	return compressed
}

func writeSM2KeyPair(baseDir, id string) error {
	priv, err := ccrypto.GenerateECKey(ccrypto.SM2Curve)
	if err != nil {
		return err
	}
	pub := priv.Public()

	privPEM, err := priv.MarshalPKCS8PrivateKeyPEM()
	if err != nil {
		return err
	}
	pubPEM, err := pub.MarshalPKIXPublicKeyPEM()
	if err != nil {
		return err
	}

	dir := filepath.Join(baseDir, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "private_key.pem"), privPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "public_key.pem"), pubPEM, 0o644); err != nil {
		return err
	}
	return nil
}

func TestBuildWireMessageUsesDefaultCodec(t *testing.T) {
	cfg := &Config{}
	payload := buildWireMessage(t, cfg, "peer", "hello")
	if len(payload) == 0 {
		t.Fatalf("expected non-empty payload")
	}

	// sanity check: can decode the payload back into Req
	comp := compressor.NewGzipCompressor()
	decoded, err := comp.DecompressWithPool(payload)
	if err != nil {
		t.Fatalf("decompress payload: %v", err)
	}
	var req Req
	if err := encoder.NewGobEncoder().Decode(decoded, &req); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if len(req.Data) == 0 {
		t.Fatalf("expected data in decoded payload")
	}
}

type relayKey struct {
	id   string
	peer string
}

type relayConn struct {
	ws *websocket.Conn
	mu sync.Mutex
}

type relayServer struct {
	t        *testing.T
	upgrader websocket.Upgrader
	mu       sync.Mutex
	conns    map[relayKey]*relayConn
}

func newRelayServer(t *testing.T) *relayServer {
	return &relayServer{
		t:        t,
		upgrader: websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }},
		conns:    make(map[relayKey]*relayConn),
	}
}

func (s *relayServer) handler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	peer := r.URL.Query().Get("peer")
	if id == "" || peer == "" {
		http.Error(w, "missing id or peer", http.StatusBadRequest)
		return
	}
	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	key := relayKey{id: id, peer: peer}
	rc := &relayConn{ws: ws}

	s.mu.Lock()
	s.conns[key] = rc
	s.mu.Unlock()

	go s.readLoop(key, rc)
}

func (s *relayServer) readLoop(key relayKey, rc *relayConn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, key)
		s.mu.Unlock()
		_ = rc.ws.Close()
	}()
	for {
		msgType, msg, err := rc.ws.ReadMessage()
		if err != nil {
			return
		}
		dest := s.getConn(relayKey{id: key.peer, peer: key.id})
		if dest == nil {
			continue
		}
		dest.mu.Lock()
		werr := dest.ws.WriteMessage(msgType, msg)
		dest.mu.Unlock()
		if werr != nil {
			return
		}
	}
}

func (s *relayServer) getConn(key relayKey) *relayConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns[key]
}

func (s *relayServer) waitForConn(t *testing.T, key relayKey, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.getConn(key) != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("relay connection not ready: %s->%s", key.id, key.peer)
}

func dialRelay(t *testing.T, baseURL, id, peer string) *websocket.Conn {
	wsURL := "ws" + strings.TrimPrefix(baseURL, "http")
	wsURL = fmt.Sprintf("%s?id=%s&peer=%s", wsURL, id, peer)
	ws, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial relay (%s->%s): %v", id, peer, err)
	}
	return ws
}

func TestRelayConcurrentMessaging(t *testing.T) {
	keystore := t.TempDir()
	ids := []string{"A", "B", "C"}
	for _, id := range ids {
		if err := writeSM2KeyPair(keystore, id); err != nil {
			t.Fatalf("write keys for %s: %v", id, err)
		}
	}

	cfg := &Config{KeyStorePath: keystore}

	relay := newRelayServer(t)
	srv := httptest.NewServer(http.HandlerFunc(relay.handler))
	defer srv.Close()

	// A<->B and A<->C use separate relay links (one ws per pair per client).
	aToBWS := dialRelay(t, srv.URL, "A", "B")
	bToAWS := dialRelay(t, srv.URL, "B", "A")
	aToCWS := dialRelay(t, srv.URL, "A", "C")
	cToAWS := dialRelay(t, srv.URL, "C", "A")
	defer aToBWS.Close()
	defer bToAWS.Close()
	defer aToCWS.Close()
	defer cToAWS.Close()

	relay.waitForConn(t, relayKey{id: "A", peer: "B"}, 2*time.Second)
	relay.waitForConn(t, relayKey{id: "B", peer: "A"}, 2*time.Second)
	relay.waitForConn(t, relayKey{id: "A", peer: "C"}, 2*time.Second)
	relay.waitForConn(t, relayKey{id: "C", peer: "A"}, 2*time.Second)

	aToB := NewSecureConn(aToBWS, "A", cfg)
	bToA := NewSecureConn(bToAWS, "B", cfg)
	aToC := NewSecureConn(aToCWS, "A", cfg)
	cToA := NewSecureConn(cToAWS, "C", cfg)
	defer aToB.Close()
	defer bToA.Close()
	defer aToC.Close()
	defer cToA.Close()

	msgToB := buildWireMessage(t, cfg, "B", "hello-b")
	msgToC := buildWireMessage(t, cfg, "C", "hello-c")
	msgToAFromB := buildWireMessage(t, cfg, "A", "reply-b")
	msgToAFromC := buildWireMessage(t, cfg, "A", "reply-c")

	errCh := make(chan error, 4)

	go func() {
		_, data, err := bToA.ReadMessage()
		if err != nil {
			errCh <- fmt.Errorf("B read: %w", err)
			return
		}
		if !bytes.Equal(data, msgToB) {
			errCh <- fmt.Errorf("B received unexpected payload")
			return
		}
		errCh <- bToA.WriteMessage(websocket.BinaryMessage, msgToAFromB)
	}()

	go func() {
		_, data, err := cToA.ReadMessage()
		if err != nil {
			errCh <- fmt.Errorf("C read: %w", err)
			return
		}
		if !bytes.Equal(data, msgToC) {
			errCh <- fmt.Errorf("C received unexpected payload")
			return
		}
		errCh <- cToA.WriteMessage(websocket.BinaryMessage, msgToAFromC)
	}()

	writeErrCh := make(chan error, 2)
	go func() { writeErrCh <- aToB.WriteMessage(websocket.BinaryMessage, msgToB) }()
	go func() { writeErrCh <- aToC.WriteMessage(websocket.BinaryMessage, msgToC) }()
	for i := 0; i < cap(writeErrCh); i++ {
		err := <-writeErrCh
		if err != nil {
			t.Fatalf("A write failed: %v", err)
		}
	}

	go func() {
		_, data, err := aToB.ReadMessage()
		if err != nil {
			errCh <- fmt.Errorf("A read from B: %w", err)
			return
		}
		if !bytes.Equal(data, msgToAFromB) {
			errCh <- fmt.Errorf("A received unexpected payload from B")
			return
		}
		errCh <- nil
	}()

	go func() {
		_, data, err := aToC.ReadMessage()
		if err != nil {
			errCh <- fmt.Errorf("A read from C: %w", err)
			return
		}
		if !bytes.Equal(data, msgToAFromC) {
			errCh <- fmt.Errorf("A received unexpected payload from C")
			return
		}
		errCh <- nil
	}()

	for i := 0; i < cap(errCh); i++ {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("relay exchange failed: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timeout waiting for relay exchange")
		}
	}
}
