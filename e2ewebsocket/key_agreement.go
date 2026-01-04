package e2ewebsocket

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	ccrypto "github.com/albert/ws_client/crypto"
	"github.com/albert/ws_client/crypto/ecdh_curve"
	"github.com/albert/ws_client/crypto/sm2keyexch"
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
	preMasterSecret       []byte
	localStaticPrivateKey *ccrypto.ECKey
	remoteStaticPublicKey *ccrypto.ECKey
	localId               string
	remoteId              string
	ctxLocal              *sm2keyexch.KAPCtx
	kxmLocal              *keyExchangeMsg
	// keyLen                int
}

func NewSM2KeyAgreement(local *ccrypto.ECKey, localId string, remote *ccrypto.ECKey, remoteId string) *sm2KeyAgreement {
	ctxLocal := sm2keyexch.NewKAPCtx()
	if err := ctxLocal.Init(local, localId, remote, remoteId, true, true); err != nil {
		return nil
	}
	return &sm2KeyAgreement{
		localStaticPrivateKey: local,
		localId:               localId,
		remoteStaticPublicKey: remote,
		remoteId:              remoteId,
		ctxLocal:              ctxLocal,
		// keyLen:                keyLen,
	}
}

// 这本来就是 sm2 交换的密钥处理逻辑函数，无需考虑兼容性
func (ka *sm2KeyAgreement) processRemoteKeyExchange(config *Config, hello *helloMsg, remoteHello *helloMsg, kxm *keyExchangeMsg) error {
	// 第一部分：验证临时公钥
	if len(kxm.key) < 4 {
		return errKeyExchange
	}
	if kxm.key[0] != 3 { // named curve
		return errors.New("remote used unsupported curve")
	}
	// sm2 密钥交换是没有 curve 可以选的
	// 所以这里得到 curveID 直接校验对不对就行了，解析出别的 curve 都算失败
	curveID := CurveID(kxm.key[1])<<8 | CurveID(kxm.key[2])
	if curveID != SM2CurveP256V1 {
		return errors.New("remote used unsupported curve")
	}

	// 在这里基于ka新建curve
	sm2Curve := ecdh_curve.NewSm2P256V1(true)

	// publicKey 是 RB
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

	// 到这里，双方id以及静态的公私钥其实都是有的，但是从哪传进来?
	// 比如生成 sm2 的 KA 的时候，所以会出现和不同的人协商 suite 是一样的，但是 ka 是不同的
	// 那是不是和不同人，handshakeState也不同？

	// sm2 密钥交换是没有 curve 可以选的
	// if _, ok := curveForCurveID(curveID); !ok {
	// 	return errors.New("remote used unsupported curve")
	// }

	// 产生临时私钥（sm2 似乎不需要这一步，在ecdh内部完成了）
	// key, err := generateECDHEKey(config.rand(), curveID)
	// if err != nil {
	// 	return err
	// }
	// ka.key = key

	// 有 RB 了直接发起ecdh即可，但是 curve 的 ecdh 方法要通过临时私钥的 ECDH 来调用
	// 而 sm2 交换中没有临时私钥
	// ecdh 有必要做到 curve 上吗，有必要做接口兼容吗

	// 新建一个空privateKey 纯粹是为了调用curve的ecdh绕的远路，因为sm2没有显示的临时私钥，
	// 所以说有没有必要做兼容，这些都是兼容带来的代价，兼容带来的优势是？
	key := ecdh_curve.NewEmptySm2PrivateKey(sm2Curve)

	// 把 RB 放到 PublicKey 结构体里面
	peerKey, err := key.Curve().NewPublicKey(publicKey)
	if err != nil {
		return errServerKeyExchange
	}

	ka.preMasterSecret, err = key.ECDH(peerKey)
	if err != nil {
		return errServerKeyExchange
	}

	// 把自己的临时公钥做成 clientKeyExchangeMsg【放到下面去！】
	// ourPublicKey := key.PublicKey().Bytes()
	// ka.ckx = new(clientKeyExchangeMsg)
	// ka.ckx.ciphertext = make([]byte, 1+len(ourPublicKey))
	// ka.ckx.ciphertext[0] = byte(len(ourPublicKey))
	// copy(ka.ckx.ciphertext[1:], ourPublicKey)

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

func (ka *sm2KeyAgreement) generateLocalKeyExchange(config *Config, clientHello *helloMsg, cert *x509.Certificate) ([]byte, *keyExchangeMsg, error) {
	// 把上面函数里面关于生成ckx的逻辑移到这边来
	// 并且在 doFullHnadshake 函数中先调用这个函数，把自己的信息发出去，再处理对方的
	// 因为此时密钥套件已经选定了，所以依据协商出的密码套件进行生成，而不是依据对方发送的 ServerKeyExchange 中的信息
	// if ka.ckx == nil {
	// 	return nil, nil, errors.New("tls: missing ServerKeyExchange message")
	// }

	// return ka.preMasterSecret, ka.ckx, nil

	// 生成本地临时公钥对后面放到外面去才对称

	// ourPublicKey := key.PublicKey().Bytes()
	RA, err := ka.ctxLocal.Prepare()
	if err != nil {
		return nil, nil, err
	}
	ka.kxmLocal = new(keyExchangeMsg)
	ka.kxmLocal.key = make([]byte, 1+len(RA))
	ka.kxmLocal.key[0] = byte(len(RA))
	copy(ka.kxmLocal.key[1:], RA)

	return RA, ka.kxmLocal, nil
}

func (k *sm2KeyAgreement) Prepare(remotePub *ccrypto.ECKey, remoteId string, initiator bool, doChecksum bool) ([]byte, error) {

	if err := k.ctxLocal.Init(k.localStaticPrivateKey, k.localId, remotePub, remoteId, initiator, doChecksum); err != nil {
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
