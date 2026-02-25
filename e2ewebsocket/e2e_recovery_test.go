package e2ewebsocket

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/albert/ws_client/encoder"
	"github.com/gorilla/websocket"
	"github.com/openimsdk/protocol/sdkws"
	"google.golang.org/protobuf/proto"
)

// TestE2E_SessionRecovery simulates a scenario where a session is corrupted/destroyed
// and verifies that the system automatically recovers (re-handshakes) and continues communication.
func TestE2E_SessionRecovery(t *testing.T) {
	// 1. Environment Setup (Reusing keys from static_key)
	cwd, _ := os.Getwd()
	keyStorePath := filepath.Join(filepath.Dir(cwd), "static_key")
	if _, err := os.Stat(keyStorePath); os.IsNotExist(err) {
		t.Skipf("static_key dir not found at %s", keyStorePath)
	}

	// 2. Start Mock Server (Broadcast Server)
	// We need a slightly more sophisticated mock server that we can tamper with traffic?
	// Or we can just tamper with it on the client side sending path?
	// Let's tamper on the client side sending path by modifying the Conn to send garbage.

	ms := newMockServer()
	s := httptest.NewServer(http.HandlerFunc(ms.handler))
	defer s.Close()
	wsUrl := "ws" + strings.TrimPrefix(s.URL, "http")

	// 3. Config
	mockComp := &MockCompressor{}
	cfgAlice := &Config{KeyStorePath: keyStorePath, Compressor: mockComp, Encoder: encoder.NewGobEncoder()}
	cfgBob := &Config{KeyStorePath: keyStorePath, Compressor: mockComp, Encoder: encoder.NewGobEncoder()}

	// 4. Connect Alice (1111111111) and Bob (2222222222)
	wsAlice, _, err := websocket.DefaultDialer.Dial(wsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	connAlice := NewSecureConn(wsAlice, "1111111111", cfgAlice)
	defer connAlice.Close()

	wsBob, _, err := websocket.DefaultDialer.Dial(wsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	connBob := NewSecureConn(wsBob, "2222222222", cfgBob)
	defer connBob.Close()

	// Helper to read 1 message from Bob
	readFromBob := func() string {
		// Set timeout
		err := connBob.SetReadDeadline(5 * time.Second)
		if err != nil {
			t.Fatal(err)
		}

		// In our self-healing logic, readLoop consumes the bad message/alert and continues.
		// So ReadMessage call here should BLOCK until the NEXT valid message arrives
		// or return an error if the connection dies effectively.

		_, msg, err := connBob.ReadMessage()
		if err != nil {
			t.Fatalf("Bob ReadMessage failed: %v", err)
		}

		// Decode
		var req Req
		dec := encoder.NewGobEncoder()
		if err := dec.Decode(msg, &req); err != nil {
			t.Fatalf("Bob deccode req failed: %v", err)
		}
		var msgData sdkws.MsgData
		if err := proto.Unmarshal(req.Data, &msgData); err != nil {
			t.Fatalf("Bob unmarshal proto failed: %v", err)
		}
		return string(msgData.Content)
	}

	// 5. Phase 1: Normal Communication
	// Alice sends "Seq 1"
	payload1 := makeAppMsg(t, "1111111111", "2222222222", []byte("Seq 1"))
	if err := connAlice.WriteMessage(websocket.BinaryMessage, payload1); err != nil {
		t.Fatalf("Alice write 1 failed: %v", err)
	}

	received1 := readFromBob()
	if received1 != "Seq 1" {
		t.Errorf("Expected 'Seq 1', got '%s'", received1)
	}
	t.Log("Phase 1: Normal message success")

	// 6. Phase 2: Simulating Corruption to trigger Alert & Recovery
	// We want to simulate Alice sending a message that Bob fails to decrypt.
	// Since we can't easily inject into the middle without a proxy,
	// let's manually write a "Bad Record" to Bob's underlying websocket,
	// spoofing it as coming from Alice.
	//
	// To do this correctly, we need to construct a packet that LOOKS like an ApplicationData packet from Alice
	// but has garbage ciphertext.

	// Create a valid header structure
	// [1 byte Type][10 byte HostID][Encrypted Data...]
	// Type = 23 (ApplicationData)
	// HostId = "1111111111"

	badPacket := make([]byte, 11)
	badPacket[0] = byte(recordTypeApplicationData)
	copy(badPacket[1:11], "1111111111") // not padded because it's exactly 10 bytes

	// Append garbage ciphertext
	badPacket = append(badPacket, []byte("garbage_ciphertext_12345")...)

	// Alice writes this garbage directly to the socket, bypassing the encryption layer
	// (Simulating a man-in-the-middle or memory corruption)
	// connAlice.conn.WriteMessage(...)
	// But wait, connAlice.conn is the WS connection.

	t.Log("Phase 2: Injecting bad record...")
	if err := connAlice.conn.WriteMessage(websocket.BinaryMessage, badPacket); err != nil {
		t.Fatal(err)
	}

	// Now Bob's readLoop should:
	// 1. Receive packet
	// 2. Identify session "alice"
	// 3. Try to decrypt -> Fail
	// 4. Send Alert(BadRecordMAC) to Alice
	// 5. Delete session "alice"
	// 6. Continue loop

	// Alice's readLoop should:
	// 1. Receive Alert from Bob
	// 2. Delete session "bob"

	// Give it a moment to propagate
	time.Sleep(100 * time.Millisecond)

	// verify that Bob's session for alice is gone or marked error (internal check, optional)
	// We rely on the behavior test: Can they talk again?

	// 7. Phase 3: Recovery
	// Alice sends "Seq 2"
	// This call to WriteMessage should detect that the session is missing (due to Alert reception)
	// OR, if Alice hasn't processed the Alert yet, it might send with the OLD session.
	//
	// Scenario A: Alice processed Alert -> Session deleted -> WriteMessage triggers NEW Handshake -> Success
	// Scenario B: Alice didn't process Alert yet -> Session exists -> WriteMessage encrypts with OLD key -> Sends to Bob
	//             -> Bob has deleted session -> Bob receives data for unknown session -> Creates Passive Session -> Handshake?
	//             No, Bob checks session map, nil -> triggers passive handshake.
	//             But the data is encrypted with OLD key. Bob's new session expects ClientHello or new key.
	//             Bob will fail to read this message as a Handshake? Or fail decrypt?
	//
	//             Wait, if Bob deleted session, he treats it as a NEW session request.
	//             Data comes in. It's ApplicationData type.
	//             Bob code: if session == nil { NewSession; go Handshake() }
	//             Then checks session.in.decrypt()...
	//             The passive handshake runs in background.
	//             The main loop tries to decrypt 'msg'.
	//             BUT 'msg' is encrypted with OLD key.
	//             The NEW session has default/nil keys until handshake finishes?
	//             Actually, NewSession keys are empty. Decrypt will fail?
	//
	//             This reveals a race/synchronization nuance.
	//             The 'Lazy Recreation' works best if the Sender knows to restart.
	//             Alice MUST receive the Alert and delete her session for clean recovery.

	t.Log("Phase 3: Attempting recovery message...")
	payload2 := makeAppMsg(t, "1111111111", "2222222222", []byte("Seq 2"))

	// Retry loop to allow for Alert propagation and Handshake
	success := false
	for i := 0; i < 3; i++ {
		time.Sleep(500 * time.Millisecond)
		err := connAlice.WriteMessage(websocket.BinaryMessage, payload2)
		if err != nil {
			t.Logf("Write failed (expected during recovering): %v", err)
			continue
		}

		// If write success, try to read
		// Note: The first write might trigger the handshake, but not carry the data effectively if packet loss happens?
		// Actually WriteMessage waits for Handshake if triggers new one.

		received2 := readFromBob()
		if received2 == "Seq 2" {
			success = true
			break
		}
	}

	if !success {
		t.Fatal("Failed to recover session and exchange 'Seq 2'")
	}
	t.Log("Phase 3: Recovery success! Session healed.")
}
