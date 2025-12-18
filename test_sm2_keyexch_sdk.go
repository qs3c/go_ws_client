//go:build testsdk

package main

import (
	"fmt"

	"github.com/albert/ws_client/sm2keyexch"

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
}

func printHex(label string, buf []byte) {
	fmt.Printf("%s", label)
	for _, b := range buf {
		fmt.Printf("%02X", b)
	}
	fmt.Println()
}
