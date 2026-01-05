package e2ewebsocket

import (
	"crypto"
	"crypto/sha1"
	"errors"

	ccrypto "github.com/albert/ws_client/crypto"
	"github.com/albert/ws_client/crypto/ecdh_curve"
	"github.com/albert/ws_client/crypto/sm2keyexch"
	"github.com/albert/ws_client/crypto/sm3tongsuo"
)

var errKeyExchange = errors.New("invalid KeyExchange message")

type keyAgreement interface {
	generateLocalKeyExchange(*Config, *helloMsg) (*keyExchangeMsg, error)
	processRemoteKeyExchange(*Config, SignatureScheme, *helloMsg, *helloMsg, *keyExchangeMsg) ([]byte, error)
}

// type keyAgreement interface {
// 	Prepare(remotePub *sm2keyexch.ECKey, remoteId string, initiator bool, doChecksum bool) ([]byte, error)
// 	ComputeKey(remotePoint []byte, keyLen int) ([]byte, []byte, error)
// }

type sm2KeyAgreement struct {
	version               uint16
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

func (ka *sm2KeyAgreement) generateLocalKeyExchange(config *Config, localHello *helloMsg) (*keyExchangeMsg, error) {
	// 产生 RA 放到 kxm 的 key 中
	RA, err := ka.ctxLocal.Prepare()
	if err != nil {
		return nil, err
	}
	ka.kxmLocal = new(keyExchangeMsg)
	ka.kxmLocal.key = make([]byte, 1+len(RA))
	ka.kxmLocal.key[0] = byte(len(RA))
	copy(ka.kxmLocal.key[1:], RA)

	return ka.kxmLocal, nil
}

// 这本来就是 sm2 交换的密钥处理逻辑函数，无需考虑兼容性
func (ka *sm2KeyAgreement) processRemoteKeyExchange(config *Config, signatureScheme SignatureScheme, hello *helloMsg, remoteHello *helloMsg, kxm *keyExchangeMsg) error {
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
	// 谁 id 大谁是 initiator
	sm2Curve := ecdh_curve.NewSm2P256V1(ka.localId > ka.remoteId)

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
		return errKeyExchange
	}

	ka.preMasterSecret, err = key.ECDH(peerKey)
	if err != nil {
		return errKeyExchange
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

	// if !isSupportedSignatureAlgorithm(signatureAlgorithm, hello.supportedSignatureAlgorithms) {
	// 	return errors.New("tls: certificate used with invalid signature algorithm")
	// }

	// 核对一下跟pick选择的是不是一个
	if signatureAlgorithm != signatureScheme {
		return errors.New("used with invalid signature algorithm")
	}
	sigType, sigHash, err = typeAndHashFromSignatureScheme(signatureScheme)
	if err != nil {
		return err
	}

	// if (sigType == signaturePKCS1v15 || sigType == signatureRSAPSS) != ka.isRSA {
	if sigType != signatureSM2 {
		// SM2 密钥协商中不可以用其他签名只能用 SM2	 签名
		return errKeyExchange
	}

	sigLen := int(sig[0])<<8 | int(sig[1])
	if sigLen+2 != len(sig) {
		return errKeyExchange
	}
	sig = sig[2:]

	signed := hashForKeyExchange(sigType, sigHash, ka.version, hello.random, remoteHello.random, remoteECDHEParams)
	if err := verifyHandshakeSignature(sigType, ka.remoteStaticPublicKey, sigHash, signed, sig); err != nil {
		return errors.New("tls: invalid signature by the server certificate: " + err.Error())
	}
	return nil
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
func hashForKeyExchange(sigType uint8, hashFunc crypto.Hash, version uint16, slices ...[]byte) []byte {
	if sigType == signatureEd25519 {
		var signed []byte
		for _, slice := range slices {
			signed = append(signed, slice...)
		}
		return signed
	}
	if sigType == signatureECDSA {
		return sha1Hash(slices)
	}
	// SM3 特别处理
	if hashFunc == ccrypto.SM3 {
		hash := sm3tongsuo.NewSM3()
		for _, slice := range slices {
			hash.Write(slice)
		}
		return hash.Sum(nil)
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
