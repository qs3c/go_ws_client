package test

import (
	"fmt"
	"testing"

	"bytes"
	"crypto/rand"
	"encoding/hex" // Added for hex.EncodeToString

	ccrypto "github.com/albert/ws_client/crypto"
	"github.com/albert/ws_client/crypto/sm2keyexch"
	"github.com/albert/ws_client/crypto/sm2tongsuo"
	"github.com/albert/ws_client/crypto/sm3tongsuo" // Added as per instruction
	"github.com/albert/ws_client/crypto/sm4tongsuo"
)

func TestCryptoTools_SM2_KeyExchange(t *testing.T) {

	local, err := ccrypto.NewECKeySM2()
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	remote, err := ccrypto.NewECKeySM2()
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	localPub, err := ccrypto.NewECKeySM2()
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	remotePub, err := ccrypto.NewECKeySM2()
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}

	defer local.Free()
	defer remote.Free()
	defer localPub.Free()
	defer remotePub.Free()

	if err = local.Generate(); err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	if err = remote.Generate(); err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}

	if err = localPub.SetPublicFrom(local); err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	if err = remotePub.SetPublicFrom(remote); err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}

	ctxLocal := sm2keyexch.NewKAPCtx()
	ctxRemote := sm2keyexch.NewKAPCtx()
	defer ctxLocal.Cleanup()
	defer ctxRemote.Cleanup()

	if err = ctxLocal.Init(local, "123456", remotePub, "654321", true, true); err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	if err = ctxRemote.Init(remote, "654321", localPub, "123456", false, true); err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}

	RA, err := ctxLocal.Prepare()
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	RB, err := ctxRemote.Prepare()
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}

	keyLocal, csLocal, err := ctxLocal.ComputeKey(RB, 32)
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	keyRemote, csRemote, err := ctxRemote.ComputeKey(RA, 32)
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}

	if err = ctxLocal.FinalCheck(csRemote); err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	if err = ctxRemote.FinalCheck(csLocal); err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}

	if len(keyLocal) != len(keyRemote) {
		fmt.Println("SM2 KAP failed")
		return
	}
	for i := range keyLocal {
		if keyLocal[i] != keyRemote[i] {
			fmt.Println("SM2 KAP failed")
			return
		}
	}

	printHex("SharedKey:", keyLocal)
	printHex("ChecksumLocal:", csLocal)
	printHex("ChecksumRemote:", csRemote)

	fmt.Println("\n--- Testing Serialization Functions ---")

	// 1. Serialize Private Key
	privBytes, err := local.SerializePrivateKey()
	if err != nil {
		fmt.Printf("SerializePrivateKey failed: %v\n", err)
		return
	}
	printHex("Serialized Private Key: ", privBytes)
	fmt.Printf("len(privBytes): %d\n", len(privBytes))
	// 2. Deserialize Private Key
	newLocal, err := ccrypto.NewECKeyFromPrivateKey(privBytes)
	if err != nil {
		fmt.Printf("NewECKeyFromPrivateKey failed: %v\n", err)
		return
	}
	defer newLocal.Free()
	fmt.Println("NewECKeyFromPrivateKey success")

	// Verify Private Key Integrity
	privBytes2, err := newLocal.SerializePrivateKey()
	if err != nil {
		fmt.Printf("SerializePrivateKey (new) failed: %v\n", err)
		return
	}
	if string(privBytes) == string(privBytes2) {
		fmt.Println(">> Private Key Verified: Original and deserialized keys match.")
	} else {
		fmt.Println(">> Private Key Mismatch!")
	}

	// 3. Serialize Public Key
	pubBytes, err := localPub.SerializePublicKey()
	if err != nil {
		fmt.Printf("SerializePublicKey failed: %v\n", err)
		return
	}
	printHex("Serialized Public Key: ", pubBytes)
	fmt.Printf("len(pubBytes): %d\n", len(pubBytes))
	// 4. Deserialize Public Key
	newPub, err := ccrypto.NewECKeyFromPublicKey(pubBytes)
	if err != nil {
		fmt.Printf("NewECKeyFromPublicKey failed: %v\n", err)
		return
	}
	defer newPub.Free()
	fmt.Println("NewECKeyFromPublicKey success")

	// Verify Public Key Integrity
	pubBytes2, err := newPub.SerializePublicKey()
	if err != nil {
		fmt.Printf("SerializePublicKey (new) failed: %v\n", err)
		return
	}
	if string(pubBytes) == string(pubBytes2) {
		fmt.Println(">> Public Key Verified: Original and deserialized keys match.")
	} else {
		fmt.Println(">> Public Key Mismatch!")
	}
}

func TestCryptoTools_SM2(t *testing.T) {
	// 1. Generate Key
	priv, err := sm2tongsuo.GenerateKey()
	if err != nil {
		t.Fatal("GenerateKey failed:", err)
	}
	t.Log("SM2 operations GenerateKey verified")
	// Note: priv uses runtime.SetFinalizer for cleanup, no explicit Free() needed based on key.go implementation

	msg := []byte("test message for sm2")

	// 2. SignASN1 / VerifyASN1
	sig, err := sm2tongsuo.SignASN1(priv, msg)
	if err != nil {
		t.Fatal("SignASN1 failed:", err)
	}

	// priv implements EVPPrivateKey which embeds EVPPublicKey, so it can be used directly
	// pub := priv.Public() 可以转成公钥，但是私钥包含了公钥及其全部功能
	// EVPPrivate 接口是包含 EVPPublic 接口的，所以这里可以直接输入 priv 不用转换
	if err := sm2tongsuo.VerifyASN1(priv, msg, sig); err != nil {
		t.Fatal("VerifyASN1 failed:", err)
	}
	t.Log("SM2 operations SignASN1/VerifyASN1 verified")

	// 3. Sign / Verify (BigInt)
	r, s, err := sm2tongsuo.Sign(priv, msg)
	if err != nil {
		t.Fatal("Sign failed:", err)
	}
	if err := sm2tongsuo.Verify(priv, msg, r, s); err != nil {
		t.Fatal("Verify failed:", err)
	}
	t.Log("SM2 operations Sign/Verify verified")

	// 4. Encrypt / Decrypt
	ciphertext, err := sm2tongsuo.Encrypt(priv, msg)
	if err != nil {
		t.Fatal("Encrypt failed:", err)
	}

	plaintext, err := sm2tongsuo.Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatal("Decrypt failed:", err)
	}

	if !bytes.Equal(msg, plaintext) {
		t.Errorf("Decrypt mismatch. Got %x, want %x", plaintext, msg)
	}

	t.Log("SM2 operations Enc/Dec verified")
}

func TestCryptoTools_SM3(t *testing.T) {
	// 1. One-shot hash test
	data := []byte("abc")
	// Standard SM3("abc") = 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
	expected := "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"

	sum := sm3tongsuo.Sum(data)
	// 32 字节数组转为 16 进制字符串
	sumHex := hex.EncodeToString(sum[:])
	if sumHex != expected {
		t.Errorf("SM3 Sum mismatch. Got %s, want %s", sumHex, expected)
	} else {
		t.Log("SM3 Sum('abc') verified")
	}

	// 2. Streaming hash test
	h := sm3tongsuo.NewSM3()
	if h == nil {
		t.Fatal("NewSM3 failed")
	}
	h.Write([]byte("a"))
	h.Write([]byte("b"))
	h.Write([]byte("c"))
	streamingSum := h.Sum(nil)
	streamingHex := hex.EncodeToString(streamingSum)

	if streamingHex != expected {
		t.Errorf("SM3 Streaming mismatch. Got %s, want %s", streamingHex, expected)
	} else {
		t.Log("SM3 Streaming('abc') verified")
	}

	// 可接续加入
	h.Write([]byte("e"))
	h.Write([]byte("f"))
	h.Write([]byte("g"))
	streamingSum2 := h.Sum(nil)
	streamingHex2 := hex.EncodeToString(streamingSum2)

	sum2 := sm3tongsuo.Sum([]byte("abcefg"))
	sumHex2 := hex.EncodeToString(sum2[:])

	if streamingHex2 != sumHex2 {
		t.Error("SM3 forward Streaming failed.")
	} else {
		t.Log("SM3 Streaming('abcefg') verified")
	}

	// 3. Reset test
	h.Reset()
	h.Write([]byte("abc"))
	resetSum := h.Sum(nil)
	resetHex := hex.EncodeToString(resetSum)
	if resetHex != expected {
		t.Errorf("SM3 Reset mismatch. Got %s, want %s", resetHex, expected)
	} else {
		t.Log("SM3 Reset usage verified")
	}
}

func TestCryptoTools_SM4_AEAD(t *testing.T) {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("Hello SM4 GCM Mode")
	aad := []byte("Additional Auth Data")

	// 1. Encryption
	encAEAD := sm4tongsuo.NewSm4AEADCipher(key, iv, true)
	if encAEAD == nil {
		t.Fatal("NewSm4AEADCipher (Encrypt) failed")
	}

	// nonce is handled internally via iv passed to New, so we pass nil here
	ciphertext := encAEAD.Seal(nil, nil, plaintext, aad)
	if len(ciphertext) == 0 {
		t.Fatal("Encryption failed, empty ciphertext")
	}
	t.Logf("Ciphertext len: %d", len(ciphertext))

	// 2. Decryption
	decAEAD := sm4tongsuo.NewSm4AEADCipher(key, iv, false)
	if decAEAD == nil {
		t.Fatal("NewSm4AEADCipher (Decrypt) failed")
	}

	decrypted, err := decAEAD.Open(nil, nil, ciphertext, aad)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("Decryption mismatch. Got %x, want %x", decrypted, plaintext)
	}

	t.Log("SM4 GCM Encryption/Decryption Success")
}

func TestCryptoTools_PKEYtoECKEY(t *testing.T) {
	// 1. Generate an SM2 Key (which is a pKey underlying)
	priv, err := ccrypto.GenerateECKey(ccrypto.SM2Curve)
	if err != nil {
		t.Fatal("Failed to generate SM2 key:", err)
	}

	// 2. Convert to ECKey using ToECKey
	ecKey, err := ccrypto.ToECKey(priv)
	if err != nil {
		t.Fatalf("ToECKey failed: %v", err)
	}

	// 3. Verify the result
	if ecKey == nil {
		t.Fatal("ToECKey returned nil")
	}

	// Optional: Check if the EC_KEY pointer is valid (not null)
	// We can't access internal fields directly easily if they are private,
	// but if no error returned, it should be fine.
	t.Log("Successfully converted pKey to ECKey")
}

func printHex(label string, buf []byte) {
	fmt.Printf("%s", label)
	for _, b := range buf {
		fmt.Printf("%02X", b)
	}
	fmt.Println()
}
