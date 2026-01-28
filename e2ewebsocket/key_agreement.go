package e2ewebsocket

import (
	"crypto"
	"crypto/sha1"
	"errors"

	ccrypto "github.com/albert/ws_client/crypto"
	"github.com/albert/ws_client/crypto/sm2keyexch"
	"github.com/albert/ws_client/crypto/sm2tongsuo"
	"github.com/albert/ws_client/crypto/sm3tongsuo"
)

var errKeyExchange = errors.New("invalid KeyExchange message")

type keyAgreement interface {
	generateLocalKeyExchange(*Config, SignatureScheme, *helloMsg, *helloMsg) (*keyExchangeMsg, error)
	processRemoteKeyExchange(*Config, SignatureScheme, *helloMsg, *helloMsg, *keyExchangeMsg) ([]byte, error)
}

// type keyAgreement interface {
// 	Prepare(remotePub *sm2keyexch.ECKey, remoteId string, initiator bool, doChecksum bool) ([]byte, error)
// 	ComputeKey(remotePoint []byte, keyLen int) ([]byte, []byte, error)
// }

type sm2KeyAgreement struct {

	// localStaticPrivateKey *ccrypto.ECKey
	// remoteStaticPublicKey *ccrypto.ECKey
	localStaticPrivateKey ccrypto.EVPPrivateKey
	remoteStaticPublicKey ccrypto.EVPPublicKey
	localId               string
	remoteId              string
	ctxLocal              *sm2keyexch.KAPCtx
	initiator             bool

	kxmLocal        *keyExchangeMsg
	preMasterSecret []byte
	// keyLen                int
}

func NewSM2KeyAgreement(local ccrypto.EVPPrivateKey, localId string, remote ccrypto.EVPPrivateKey, remoteId string) *sm2KeyAgreement {
	// 这里要处理sm2的 eckey与pkey兼容问题，方式是 pkey 转 eckey
	localECKEY, err := ccrypto.ToECKey(local)
	if err != nil {
		return nil
	}
	remoteECKEY, err := ccrypto.ToECKey(remote)
	if err != nil {
		return nil
	}
	initiator := isInitiator(localId, remoteId)
	ctxLocal := sm2keyexch.NewKAPCtx()
	if err := ctxLocal.Init(localECKEY, localId, remoteECKEY, remoteId, initiator, true); err != nil {
		return nil
	}
	return &sm2KeyAgreement{
		localStaticPrivateKey: local,
		localId:               localId,
		remoteStaticPublicKey: remote,
		remoteId:              remoteId,
		ctxLocal:              ctxLocal,
		initiator:             initiator,
		// keyLen:                keyLen,
	}
}

func (ka *sm2KeyAgreement) initContext() error {
	if ka.ctxLocal != nil {
		return nil
	}
	if ka.localStaticPrivateKey == nil || ka.remoteStaticPublicKey == nil {
		return errors.New("missing static key material")
	}
	localECKEY, err := ccrypto.ToECKey(ka.localStaticPrivateKey)
	if err != nil {
		return err
	}
	remoteECKEY, err := ccrypto.ToECKey(ka.remoteStaticPublicKey)
	if err != nil {
		return err
	}
	if ka.localId == "" || ka.remoteId == "" {
		return errors.New("missing peer identifiers")
	}
	ctxLocal := sm2keyexch.NewKAPCtx()
	if err := ctxLocal.Init(localECKEY, ka.localId, remoteECKEY, ka.remoteId, ka.initiator, true); err != nil {
		return err
	}
	ka.ctxLocal = ctxLocal
	return nil
}

func (ka *sm2KeyAgreement) generateLocalKeyExchange(config *Config, signatureScheme SignatureScheme, hello *helloMsg, remoteHello *helloMsg) (*keyExchangeMsg, error) {
	if err := ka.initContext(); err != nil {
		return nil, err
	}
	// 1. 产生临时随机公钥 RA 放到 kxm 的 key 中
	RA, err := ka.ctxLocal.Prepare()
	if err != nil {
		return nil, err
	}
	ka.kxmLocal = new(keyExchangeMsg)
	// 可优化空间分配
	ka.kxmLocal.key = make([]byte, 4+len(RA))

	ka.kxmLocal.key[0] = byte(3) // named curve
	ka.kxmLocal.key[1] = byte(uint16(SM2CurveP256V1) >> 8)
	ka.kxmLocal.key[2] = byte(SM2CurveP256V1 & 0xFF)
	ka.kxmLocal.key[3] = byte(len(RA))
	copy(ka.kxmLocal.key[4:], RA)

	localECDHEParams := ka.kxmLocal.key[:4+len(RA)]

	// 2. 产生签名
	// 根据pick协商的 signatureScheme 来得到 sigType 和 sigHash
	sigType, sigHash, err := typeAndHashFromSignatureScheme(signatureScheme)
	if err != nil {
		return nil, err
	}
	if sigType != signatureSM2 {
		return nil, errors.New("unsupported signature scheme for SM2 key agreement")
	}
	// initiator 的随机值在前
	var signed []byte
	if ka.initiator {
		signed = hashForKeyExchange(sigType, sigHash, hello.random, remoteHello.random, localECDHEParams)
	} else {
		signed = hashForKeyExchange(sigType, sigHash, remoteHello.random, hello.random, localECDHEParams)
	}
	signature, err := sm2tongsuo.SignASN1(ka.localStaticPrivateKey, signed)
	if err != nil {
		return nil, err
	}

	// 构造：[SigScheme(2)][SigLen(2)][SigBytes...]
	// 1. Signature Scheme (2 bytes)
	ka.kxmLocal.key = append(ka.kxmLocal.key, byte(signatureScheme>>8), byte(signatureScheme))

	// 2. Signature Length (2 bytes)
	var sigLen uint16
	sigLen = uint16(len(signature))
	ka.kxmLocal.key = append(ka.kxmLocal.key, byte(sigLen>>8), byte(sigLen))

	// 3. Signature itself
	ka.kxmLocal.key = append(ka.kxmLocal.key, signature...)

	return ka.kxmLocal, nil
}

// 这本来就是 sm2 交换的密钥处理逻辑函数，无需考虑兼容性
func (ka *sm2KeyAgreement) processRemoteKeyExchange(config *Config, signatureScheme SignatureScheme, hello *helloMsg, remoteHello *helloMsg, kxm *keyExchangeMsg) ([]byte, error) {
	if err := ka.initContext(); err != nil {
		return nil, err
	}
	// 第一部分：验证临时公钥
	if len(kxm.key) < 4 {
		return nil, errKeyExchange
	}
	if kxm.key[0] != 3 { // named curve
		return nil, errors.New("remote used unsupported curve")
	}
	// sm2 密钥交换是没有 curve 可以选的
	// 所以这里得到 curveID 直接校验对不对就行了，解析出别的 curve 都算失败
	curveID := CurveID(kxm.key[1])<<8 | CurveID(kxm.key[2])
	if curveID != SM2CurveP256V1 {
		return nil, errors.New("remote used unsupported curve")
	}

	// publicKey 是 RB
	publicLen := int(kxm.key[3])
	if publicLen+4 > len(kxm.key) {
		return nil, errKeyExchange
	}
	remoteECDHEParams := kxm.key[:4+publicLen]
	publicKey := remoteECDHEParams[4:]

	sig := kxm.key[4+publicLen:]
	if len(sig) < 2 {
		return nil, errKeyExchange
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

	sharedKey, _, err := ka.ctxLocal.ComputeKey(publicKey, 32)
	if err != nil {
		return nil, errKeyExchange
	}
	ka.preMasterSecret = sharedKey

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
		return nil, errKeyExchange
	}

	// if !isSupportedSignatureAlgorithm(signatureAlgorithm, hello.supportedSignatureAlgorithms) {
	// 	return errors.New("tls: certificate used with invalid signature algorithm")
	// }

	// 核对一下跟pick选择的是不是一个
	if signatureAlgorithm != signatureScheme {
		return nil, errors.New("used with invalid signature algorithm")
	}
	sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureScheme)
	if err != nil {
		return nil, err
	}

	// if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
	if sigType != signatureSM2 {
		// SM2 密钥协商中不可以用其他签名只能用 SM2	 签名
		return nil, errKeyExchange
	}

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return nil, errKeyExchange
	}
	sig = sig[2:]
	var signed []byte
	// initiator 的随机值在前
	if ka.localId > ka.remoteId {
		signed = hashForKeyExchange(sigType, sigHash, hello.random, remoteHello.random, remoteECDHEParams)
	} else {
		signed = hashForKeyExchange(sigType, sigHash, remoteHello.random, hello.random, remoteECDHEParams)
	}
	if err := verifyHandshakeSignature(sigType, ka.remoteStaticPublicKey, sigHash, signed, sig); err != nil {
		return nil, errors.New("invalid signature by the server certificate: " + err.Error())
	}
	return ka.preMasterSecret, nil
}

// func (k *sm2KeyAgreement) Prepare(remotePub *ccrypto.ECKey, remoteId string, initiator bool, doChecksum bool) ([]byte, error) {

// 	if err := k.ctxLocal.Init(k.localStaticPrivateKey, k.localId, remotePub, remoteId, initiator, doChecksum); err != nil {
// 		fmt.Println("SM2 KAP failed")
// 		return nil, err
// 	}

// 	RA, err := k.ctxLocal.Prepare()
// 	if err != nil {
// 		fmt.Println("SM2 KAP failed")
// 		return nil, err
// 	}
// 	return RA, nil
// }

// func (k *sm2KeyAgreement) ComputeKey(remotePoint []byte) ([]byte, []byte, error) {

//		keyLocal, csLocal, err := k.ctxLocal.ComputeKey(remotePoint, k.keyLen)
//		if err != nil {
//			fmt.Println("SM2 KAP failed")
//			return nil, nil, err
//		}
//		return keyLocal, csLocal, nil
//	}
func hashForKeyExchange(sigType uint8, hashFunc crypto.Hash, slices ...[]byte) []byte {
	if sigType == signatureEd25519 {
		var signed []byte
		for _, slice := range slices {
			signed = append(signed, slice...)
		}
		return signed
	}
	// SM3 特别处理
	if hashFunc == sm3tongsuo.SM3HASH {
		// hash := sm3tongsuo.NewSM3()
		// for _, slice := range slices {
		// 	hash.Write(slice)
		// }
		// return hash.Sum(nil)
		// 如果是 SM3 则不处理【和 signatureEd25519 一样】
		var signed []byte
		for _, slice := range slices {
			signed = append(signed, slice...)
		}
		return signed

	}
	h := hashFunc.New()
	for _, slice := range slices {
		h.Write(slice)
	}
	digest := h.Sum(nil)
	return digest

}

func sha1Hash(slices [][]byte) []byte {
	hsha1 := sha1.New()
	for _, slice := range slices {
		hsha1.Write(slice)
	}
	return hsha1.Sum(nil)
}
