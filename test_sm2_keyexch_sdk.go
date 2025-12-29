////go:build testsdk

package main

import (
	"fmt"

	"github.com/albert/ws_client/crypto/sm2keyexch"
)

func main() {
	// 测试 sm2 密钥交换
	// test sdk
	local, err := sm2keyexch.NewECKeySM2()
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	remote, err := sm2keyexch.NewECKeySM2()
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	localPub, err := sm2keyexch.NewECKeySM2()
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return
	}
	remotePub, err := sm2keyexch.NewECKeySM2()
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
	newLocal, err := sm2keyexch.NewECKeyFromPrivateKey(privBytes)
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
	newPub, err := sm2keyexch.NewECKeyFromPublicKey(pubBytes)
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

func printHex(label string, buf []byte) {
	fmt.Printf("%s", label)
	for _, b := range buf {
		fmt.Printf("%02X", b)
	}
	fmt.Println()
}
