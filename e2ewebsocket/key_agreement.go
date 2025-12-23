package e2ewebsocket

import (
	"fmt"

	"github.com/albert/ws_client/sm2keyexch"
)

type keyAgreement interface {
	Prepare(remotePub *sm2keyexch.ECKey, remoteId string, initiator bool, doChecksum bool) ([]byte, error)
	ComputeKey(remotePoint []byte, keyLen int) ([]byte, []byte, error)
}

type sm2KeyAgreement struct {
	local    *sm2keyexch.ECKey
	localId  string
	ctxLocal *sm2keyexch.KAPCtx
	keyLen   int
}

func NewSM2KeyAgreement(local *sm2keyexch.ECKey, localId string, keyLen int) *sm2KeyAgreement {
	return &sm2KeyAgreement{
		local:    local,
		localId:  localId,
		ctxLocal: sm2keyexch.NewKAPCtx(),
		keyLen:   keyLen,
	}
}

func (k *sm2KeyAgreement) Prepare(remotePub *sm2keyexch.ECKey, remoteId string, initiator bool, doChecksum bool) ([]byte, error) {

	if err := k.ctxLocal.Init(k.local, k.localId, remotePub, remoteId, initiator, doChecksum); err != nil {
		fmt.Println("SM2 KAP failed")
		return nil, err
	}

	RA, err := k.ctxLocal.Prepare()
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return nil, err
	}
	return RA, nil
}

func (k *sm2KeyAgreement) ComputeKey(remotePoint []byte) ([]byte, []byte, error) {

	keyLocal, csLocal, err := k.ctxLocal.ComputeKey(remotePoint, k.keyLen)
	if err != nil {
		fmt.Println("SM2 KAP failed")
		return nil, nil, err
	}
	return keyLocal, csLocal, nil
}
