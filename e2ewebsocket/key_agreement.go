package e2ewebsocket

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/albert/ws_client/sm2keyexch"
)

var errKeyExchange = errors.New("invalid KeyExchange message")

type keyAgreement interface {
	processRemoteKeyExchange(*Config, *clientHelloMsg, *serverHelloMsg, *x509.Certificate, *serverKeyExchangeMsg) error
	generateLocalKeyExchange(*Config, *clientHelloMsg, *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error)
}

// type keyAgreement interface {
// 	Prepare(remotePub *sm2keyexch.ECKey, remoteId string, initiator bool, doChecksum bool) ([]byte, error)
// 	ComputeKey(remotePoint []byte, keyLen int) ([]byte, []byte, error)
// }

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

func (ka *sm2KeyAgreement) processRemoteKeyExchange(config *Config, hello *helloMsg, remoteHello *helloMsg, kxm *keyExchangeMsg) error {
	// 第一部分：验证临时公钥
	if len(kxm.key) < 4 {
		return errKeyExchange
	}
	if kxm.key[0] != 3 { // named curve
		return errors.New("remote used unsupported curve")
	}
	curveID := CurveID(kxm.key[1])<<8 | CurveID(kxm.key[2])

	publicLen := int(kxm.key[3])
	if publicLen+4 > len(kxm.key) {
		return errKeyExchange
	}
	remoteECDHEParams := kxm.key[:4+publicLen]
	publicKey := remoteECDHEParams[4:]

	sig := kxm.key[4+publicLen:]
	if len(sig) < 2 {
		return errKeyExchange
	}

	if _, ok := curveForCurveID(curveID); !ok {
		return errors.New("remote used unsupported curve")
	}

	// 第二部分：验证签名
	var sigType uint8
	var sigHash crypto.Hash

	signatureAlgorithm := SignatureScheme(sig[0])<<8 | SignatureScheme(sig[1])
	sig = sig[2:]
	if len(sig) < 2 {
		return errKeyExchange
	}

	if !isSupportedSignatureAlgorithm(signatureAlgorithm, clientHello.supportedSignatureAlgorithms) {
		return errors.New("tls: certificate used with invalid signature algorithm")
	}
	sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureAlgorithm)
	if err != nil {
		return err
	}

	if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
		return errKeyExchange
	}

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errKeyExchange
	}
	sig = sig[2:]

	signed := hashForServerKeyExchange(sigType, sigHash, ka.version, clientHello.random, serverHello.random, serverECDHEParams)
	if err := verifyHandshakeSignature(sigType, cert.PublicKey, sigHash, signed, sig); err != nil {
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}
	return nil
}

func (k *sm2KeyAgreement) generateLocalKeyExchange(config *Config, clientHello *clientHelloMsg, cert *x509.Certificate) ([]byte, *clientKeyExchangeMsg, error) {
	// 把上面函数里面关于生成ckx的逻辑移到这边来
	// 并且在 doFullHnadshake 函数中先调用这个函数，把自己的信息发出去，再处理对方的
	// 因为此时密钥套件已经选定了，所以依据协商出的密码套件进行生成，而不是依据对方发送的 ServerKeyExchange 中的信息
	// if ka.ckx == nil {
	// 	return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	// }

	// return ka.preMasterSecret, ka.ckx, nil

	// 生成本地临时公钥对后面放到外面去才对称
	key, err := generateECDHEKey(config.rand(), curveID)
	if err != nil {
		return err
	}
	ka.key = key

	peerKey, err := key.Curve().NewPublicKey(publicKey)
	if err != nil {
		return errKeyExchange
	}
	ka.preMasterSecret, err = key.ECDH(peerKey)
	if err != nil {
		return errKeyExchange
	}

	ourPublicKey := key.PublicKey().Bytes()
	ka.ckx = new(keyExchangeMsg)
	ka.ckx.ciphertext = make([]byte, 1+len(ourPublicKey))
	ka.ckx.ciphertext[0] = byte(len(ourPublicKey))
	copy(ka.ckx.ciphertext[1:], ourPublicKey)
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
