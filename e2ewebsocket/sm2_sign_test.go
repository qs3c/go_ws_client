package e2ewebsocket

import (
	"os"
	"path/filepath"
	"testing"

	ccrypto "github.com/qs3c/e2e-secure-ws/crypto"
	"github.com/qs3c/e2e-secure-ws/crypto/sm2tongsuo"
)

// 测试从 PEM 文件分别加载私钥和公钥后，SM2签名验签是否正常
func TestSM2SignVerifyWithSeparateKeys(t *testing.T) {
	// 1. 生成密钥
	priv, err := ccrypto.GenerateECKey(ccrypto.SM2Curve)
	if err != nil {
		t.Fatal("GenerateECKey failed:", err)
	}

	// 2. 导出私钥 PEM
	privPEM, err := priv.MarshalPKCS8PrivateKeyPEM()
	if err != nil {
		t.Fatal("MarshalPKCS8PrivateKeyPEM failed:", err)
	}

	// 3. 导出公钥 PEM
	pub := priv.Public()
	pubPEM, err := pub.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal("MarshalPKIXPublicKeyPEM failed:", err)
	}

	// 4. 写入临时文件
	dir := t.TempDir()
	privPath := filepath.Join(dir, "private_key.pem")
	pubPath := filepath.Join(dir, "public_key.pem")
	if err := os.WriteFile(privPath, privPEM, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0644); err != nil {
		t.Fatal(err)
	}

	// 5. 从文件重新加载
	loadedPriv, err := ccrypto.LoadPrivateKeyFileFromPEM(privPath)
	if err != nil {
		t.Fatal("LoadPrivateKeyFileFromPEM failed:", err)
	}
	loadedPub, err := ccrypto.LoadPublicKeyFileFromPEM(pubPath)
	if err != nil {
		t.Fatal("LoadPublicKeyFileFromPEM failed:", err)
	}

	t.Logf("priv KeyType: %d", loadedPriv.KeyType())
	t.Logf("pub KeyType: %d", loadedPub.KeyType())

	// 6. 用加载的私钥签名，用加载的公钥验签
	msg := []byte("hello sm2 sign verify test message abcdefghijklmnopqrstuvwxyz")
	sig, err := sm2tongsuo.SignASN1(loadedPriv, msg)
	if err != nil {
		t.Fatal("SignASN1 failed:", err)
	}
	t.Logf("signature length: %d", len(sig))

	if err := sm2tongsuo.VerifyASN1(loadedPub, msg, sig); err != nil {
		t.Fatalf("VerifyASN1 failed: %v", err)
	}
	t.Log("SM2 sign/verify with separately loaded PEM keys: PASS")
}
