package e2ewebsocket

import (
	"bytes"
	"crypto/rand"
	"testing"

	ccrypto "github.com/albert/ws_client/crypto"
)

func TestSM2KeyAgreementRoundTrip(t *testing.T) {
	alicePriv, err := ccrypto.GenerateECKey(ccrypto.SM2Curve)
	if err != nil {
		t.Fatalf("alice key: %v", err)
	}
	bobPriv, err := ccrypto.GenerateECKey(ccrypto.SM2Curve)
	if err != nil {
		t.Fatalf("bob key: %v", err)
	}

	aliceID := "alice"
	bobID := "bob"

	alice := &sm2KeyAgreement{
		localStaticPrivateKey: alicePriv,
		remoteStaticPublicKey: bobPriv.Public(),
		localId:               aliceID,
		remoteId:              bobID,
		initiator:             isInitiator(aliceID, bobID),
	}
	bob := &sm2KeyAgreement{
		localStaticPrivateKey: bobPriv,
		remoteStaticPublicKey: alicePriv.Public(),
		localId:               bobID,
		remoteId:              aliceID,
		initiator:             isInitiator(bobID, aliceID),
	}

	helloA := &helloMsg{random: make([]byte, 32)}
	helloB := &helloMsg{random: make([]byte, 32)}
	if _, err := rand.Read(helloA.random); err != nil {
		t.Fatalf("rand A: %v", err)
	}
	if _, err := rand.Read(helloB.random); err != nil {
		t.Fatalf("rand B: %v", err)
	}

	cfg := &Config{}

	debugKxm := func(label string, kxm *keyExchangeMsg) {
		if kxm == nil {
			t.Logf("%s: nil", label)
			return
		}
		if len(kxm.key) < 4 {
			t.Logf("%s: key too short len=%d", label, len(kxm.key))
			return
		}
		pubLen := int(kxm.key[3])
		if pubLen+4 > len(kxm.key) {
			t.Logf("%s: pubLen=%d total=%d", label, pubLen, len(kxm.key))
			return
		}
		sig := kxm.key[4+pubLen:]
		t.Logf("%s: pubLen=%d total=%d sigPart=%d", label, pubLen, len(kxm.key), len(sig))
		if len(sig) >= 2 {
			t.Logf("%s: sigAlg=0x%02x%02x", label, sig[0], sig[1])
		}
		if len(sig) >= 4 {
			sigLen := int(sig[2])<<8 | int(sig[3])
			t.Logf("%s: sigLen=%d", label, sigLen)
		}
	}
	kxmA, err := alice.generateLocalKeyExchange(cfg, SM2WithSM3, helloA, helloB)
	if err != nil {
		t.Fatalf("alice gen: %v", err)
	}
	kxmB, err := bob.generateLocalKeyExchange(cfg, SM2WithSM3, helloB, helloA)
	if err != nil {
		t.Fatalf("bob gen: %v", err)
	}

	preA, err := alice.processRemoteKeyExchange(cfg, SM2WithSM3, helloA, helloB, kxmB)
	if err != nil {
		debugKxm("alice->bob", kxmA)
		debugKxm("bob->alice", kxmB)
		t.Fatalf("alice process: %v", err)
	}
	preB, err := bob.processRemoteKeyExchange(cfg, SM2WithSM3, helloB, helloA, kxmA)
	if err != nil {
		debugKxm("alice->bob", kxmA)
		debugKxm("bob->alice", kxmB)
		t.Fatalf("bob process: %v", err)
	}

	if !bytes.Equal(preA, preB) {
		t.Fatalf("pre-master secret mismatch")
	}
}
