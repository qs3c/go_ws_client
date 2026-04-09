package test

import (
	"os"
	"testing"

	ccrypto "github.com/qs3c/e2e-secure-ws/crypto"
)

func TestKeyLoadingFromFile(t *testing.T) {
	// 1. Generate an SM2 Key
	priv, err := ccrypto.GenerateECKey(ccrypto.SM2Curve)
	if err != nil {
		t.Fatal("Failed to generate SM2 key:", err)
	}

	// 2. Export to PEM
	pem, err := priv.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		t.Fatal("Failed to marshal private key to PEM:", err)
	}

	// 3. Export to DER
	der, err := priv.MarshalPKCS1PrivateKeyDER()
	if err != nil {
		t.Fatal("Failed to marshal private key to DER:", err)
	}

	// 4. Save to temporary files
	pemFile, err := os.CreateTemp("", "key_*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(pemFile.Name()) // clean up
	if _, err := pemFile.Write(pem); err != nil {
		t.Fatal(err)
	}
	pemFile.Close()

	derFile, err := os.CreateTemp("", "key_*.der")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(derFile.Name()) // clean up
	if _, err := derFile.Write(der); err != nil {
		t.Fatal(err)
	}
	derFile.Close()

	// 5. Test Loading PEM
	loadedPrivPEM, err := ccrypto.LoadPrivateKeyFileFromPEM(pemFile.Name())
	if err != nil {
		t.Fatalf("LoadPrivateKeyFileFromPEM failed: %v", err)
	}
	if loadedPrivPEM == nil {
		t.Fatal("Loaded key is nil (PEM)")
	}

	// 6. Test Loading DER
	loadedPrivDER, err := ccrypto.LoadPrivateKeyFileFromDER(derFile.Name())
	if err != nil {
		t.Fatalf("LoadPrivateKeyFileFromDER failed: %v", err)
	}
	if loadedPrivDER == nil {
		t.Fatal("Loaded key is nil (DER)")
	}

	t.Log("Successfully loaded private keys from PEM and DER files")

	// 7. Testing Public Key
	pub := priv.Public()
	pubPEM, err := pub.MarshalPKIXPublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	pubPEMFile, err := os.CreateTemp("", "pub_*.pem")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(pubPEMFile.Name())
	if _, err := pubPEMFile.Write(pubPEM); err != nil {
		t.Fatal(err)
	}
	pubPEMFile.Close()

	loadedPubPEM, err := ccrypto.LoadPublicKeyFileFromPEM(pubPEMFile.Name())
	if err != nil {
		t.Fatalf("LoadPublicKeyFileFromPEM failed: %v", err)
	}
	if loadedPubPEM == nil {
		t.Fatal("Loaded pub key is nil (PEM)")
	}
	t.Log("Successfully loaded public key from PEM file")
}
