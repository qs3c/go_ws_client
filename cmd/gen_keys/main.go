package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/albert/ws_client/crypto"
)

func main() {
	baseDir := "./static_key"
	ids := []string{"alice", "bob"}

	for _, id := range ids {
		dir := filepath.Join(baseDir, id)
		if err := os.MkdirAll(dir, 0755); err != nil {
			panic(err)
		}

		fmt.Printf("Generating SM2 keys for %s...\n", id)
		// 生成 SM2 密钥
		priv, err := crypto.GenerateECKey(crypto.SM2Curve)
		if err != nil {
			panic(fmt.Sprintf("Failed to generate key for %s: %v", id, err))
		}

		// 保存私钥
		privPath := filepath.Join(dir, "private_key.pem")
		if err := crypto.SavePrivateKeyFileToPEM(privPath, priv); err != nil {
			panic(fmt.Sprintf("Failed to save private key for %s: %v", id, err))
		}
		fmt.Printf("Saved private key to %s\n", privPath)

		// 保存公钥
		pub := priv.Public()
		pubPath := filepath.Join(dir, "public_key.pem")
		if err := crypto.SavePublicKeyFileToPEM(pubPath, pub); err != nil {
			panic(fmt.Sprintf("Failed to save public key for %s: %v", id, err))
		}
		fmt.Printf("Saved public key to %s\n", pubPath)
	}
	fmt.Println("All keys generated successfully!")
}
