package ecdh_curve

import (
	"crypto"
	"crypto/subtle"
	"errors"
	"io"

	ccrypto "github.com/albert/ws_client/crypto"
	"github.com/albert/ws_client/crypto/sm2keyexch"
)

var (
	sm2p256v1PublicKeySize    = 91
	sm2p256v1PrivateKeySize   = 121
	sm2p256v1SharedSecretSize = 32
)

// Ensure sm2p256v1Curve implements ccrypto.KeyExchangeCurve
var _ Curve = (*sm2p256v1Curve)(nil)

var sm2p256v1 = &sm2p256v1Curve{}

type sm2p256v1Curve struct {
	initiator  bool
	doCheckSum bool
	csLocal    []byte
}

func NewSm2P256V1(initiator bool) *sm2p256v1Curve {
	return &sm2p256v1Curve{
		initiator:  initiator,
		doCheckSum: true,
	}
}

func (c *sm2p256v1Curve) String() string {
	return "SM2P256V1"
}

// 产生新的随机 eckey 并包装到 sm2PrivateKey
func (c *sm2p256v1Curve) GenerateKey(rand io.Reader) (PrivateKey, error) {
	eckey, err := ccrypto.NewECKeySM2()
	if err != nil {
		return nil, err
	}
	if err = eckey.Generate(); err != nil {
		return nil, err
	}
	// Serialize to keep consistent state
	privBytes, err := eckey.SerializePrivateKey()
	if err != nil {
		return nil, err
	}

	return c.NewPrivateKey(privBytes)
}

// eckey 的字节序列包装为 sm2PrivateKey，过程中产生了 sm2PublicKey
func (c *sm2p256v1Curve) NewPrivateKey(key []byte) (PrivateKey, error) {
	if len(key) != sm2p256v1PrivateKeySize {
		return nil, errors.New("sm2p256v1: invalid private key size")
	}

	eckey, err := ccrypto.NewECKeyFromPrivateKey(key)
	if err != nil {
		return nil, err
	}

	// Derive public key from private key
	eckeyPublic, err := ccrypto.NewECKeySM2()
	if err != nil {
		return nil, err
	}
	if err = eckeyPublic.SetPublicFrom(eckey); err != nil {
		return nil, err
	}

	eckeyPublicBytes, err := eckeyPublic.SerializePublicKey()
	if err != nil {
		return nil, err
	}

	publicKey, err := c.NewPublicKey(eckeyPublicBytes)
	if err != nil {
		return nil, err
	}

	return &sm2PrivateKey{
		curve:      c,
		privateKey: key,
		publicKey:  publicKey,
	}, nil
}

// eckeyPub 的字节序列包装为 sm2PublicKey
func (c *sm2p256v1Curve) NewPublicKey(key []byte) (PublicKey, error) {
	// 临时公钥长度是由底层 C 库（如 tongsuo）生成的 133 bytes 等各种可能。
	// 原版写死的 91 字节会导致握手包解出的 key 被拒。
	// if len(key) != sm2p256v1PublicKeySize {
	// 	return nil, errors.New("sm2p256v1: invalid public key size")
	// }

	return &sm2PublicKey{
		curve:     c,
		publicKey: key,
	}, nil

}

// 无需输入本地的临时私钥，只需输入对方的临时公钥 RB，实际使用时第一个入参填 nil
func (c *sm2p256v1Curve) ecdh(local PrivateKey, remote PublicKey) (keyLocal []byte, err error) {
	if local != nil {
		return nil, errors.New("sm2p256v1: local private key needed to be nil")
	}
	if remote == nil {
		return nil, errors.New("sm2p256v1: remote public key (RB) cant be nil")
	}
	_, ok := remote.(*sm2PublicKey)
	if !ok {
		return nil, errors.New("sm2p256v1: remote public key type mismatch")
	}
	// RB := remotePublicKey.publicKey

	// 临时废弃，防误调
	return nil, errors.New("sm2p256v1: do not use standard ecdh, use ComputeSecret with KAPCtx")
}

// --- PrivateKey Implementation ---

type sm2PrivateKey struct {
	curve      Curve
	privateKey []byte
	publicKey  PublicKey
}

// 给一个获取空sm2PrivateKey的方法

func NewEmptySm2PrivateKey(sm2Curve Curve) *sm2PrivateKey {
	return &sm2PrivateKey{
		curve: sm2Curve,
	}
}

// 比较两个私钥是否相等
func (k *sm2PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(*sm2PrivateKey)
	if !ok {
		return false
	}
	return k.curve == xx.curve &&
		subtle.ConstantTimeCompare(k.privateKey, xx.privateKey) == 1
}
func (k *sm2PrivateKey) Bytes() []byte {
	// 优化内存分配，避免逃逸
	var buf [121]byte
	return append(buf[:0], k.privateKey...)
}
func (k *sm2PrivateKey) Curve() Curve {
	return k.curve
}

// 输入对方公钥计算共享密钥，本质调用曲线的 ecdh 函数
// 【存疑问题RB一个字节序列怎么作为PublickKey传入，它可以被正确序列化成PublicKey吗，这要试了才知道】
func (k *sm2PrivateKey) ECDH(remote PublicKey) ([]byte, error) {
	if remote == nil {
		return nil, errors.New("sm2p256v1: remote public key (RB) cant be nil")
	}
	remotePublicKey, ok := remote.(*sm2PublicKey)
	if !ok {
		return nil, errors.New("sm2p256v1: remote public key type mismatch")
	}
	if remotePublicKey.curve != k.curve {
		return nil, errors.New("sm2p256v1: remote public key curve mismatch")
	}
	return k.curve.ecdh(nil, remotePublicKey)
}

// 独有的计算共享密钥函数，它能携带在 Init 和 Prepare 后真正有用的 ctxLocal 进去算
func (k *sm2PrivateKey) ComputeSecret(ctxLocal *sm2keyexch.KAPCtx, remote PublicKey) ([]byte, error) {
	if remote == nil {
		return nil, errors.New("sm2p256v1: remote public key (RB) cant be nil")
	}
	remotePublicKey, ok := remote.(*sm2PublicKey)
	if !ok {
		return nil, errors.New("sm2p256v1: remote public key type mismatch")
	}
	if remotePublicKey.curve != k.curve {
		return nil, errors.New("sm2p256v1: remote public key curve mismatch")
	}

	RB := remotePublicKey.publicKey

	// ecdh里面只做 Compute key 和 FinalCheck 都做不了
	keyLocal, _, err := ctxLocal.ComputeKey(RB, 32)
	if err != nil {
		return nil, err
	}
	// 怎么把RA csLocal 传出去，怎么把csRemote弄进来

	// if err := ctxLocal.FinalCheck(c.csRemote); err != nil {
	// 	return nil, err
	// }

	return keyLocal, nil
}
func (k *sm2PrivateKey) PublicKey() PublicKey {
	return k.publicKey
}
func (k *sm2PrivateKey) Public() crypto.PublicKey {
	return k.PublicKey()
}

// func (k *PrivateKey) Equal(x ccrypto.PrivateKey) bool {
// 	other, ok := x.(*PrivateKey)
// 	if !ok {
// 		return false
// 	}
// 	return bytes.Equal(k.privateKey, other.privateKey)
// }

// func (k *PrivateKey) PublicKey() ccrypto.PublicKey {
// 	return k.publicKey
// }

// func (k *PrivateKey) Bytes() []byte {
// 	return bytes.Clone(k.privateKey)
// }

// func (k *PrivateKey) ECDH(remote ccrypto.PublicKey) ([]byte, error) {
// 	other, ok := remote.(*PublicKey)
// 	if !ok {
// 		return nil, errors.New("sm2p256v1: public key type mismatch")
// 	}

// Perform SM2 Key Exchange
// Note: We need to use the ecdh method on the curve or logic similar to it.
// The original code had an 'ecdh' method on the curve. Let's reuse that logic here.
// But 'ecdh' method needed localID, remoteID, RB.
// Standard ECDH doesn't usually take IDs or RB.
// If SM2 ECDH strictly requires them, we might have to use default values or
// specific fields if this 'PrivateKey' is strictly for standard ECDH usage.
// However, since we defined the interface, maybe we can't easily pass explicit IDs here
// unless we bake them into the key or curve.
// For now, let's assume standard behavior or use fields from the curve struct if available.

// The curve struct has localID and remoteID.
// 	return k.curve.ecdh(k.ecKey, k.curve.localID, other.ecKey, k.curve.remoteID, nil)
// }

// --- PublicKey Implementation ---

type sm2PublicKey struct {
	curve     Curve
	publicKey []byte
}

func (k *sm2PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(*sm2PublicKey)
	if !ok {
		return false
	}
	return k.curve == xx.curve &&
		subtle.ConstantTimeCompare(k.publicKey, xx.publicKey) == 1
}
func (k *sm2PublicKey) Bytes() []byte {
	// 优化内存分配，避免逃逸
	var buf [91]byte
	return append(buf[:0], k.publicKey...)
}
func (k *sm2PublicKey) Curve() Curve {
	return k.curve
}

// func (k *PublicKey) Equal(x ccrypto.PublicKey) bool {
// 	other, ok := x.(*PublicKey)
// 	if !ok {
// 		return false
// 	}
// 	return bytes.Equal(k.publicKey, other.publicKey)
// }

// func (k *PublicKey) Bytes() []byte {
// 	return bytes.Clone(k.publicKey)
// }

// --- Internal ECDH Logic ---

// func (c *sm2p256v1Curve) ecdh(local *ccrypto.ECKey, localID string, remote *ccrypto.ECKey, remoteID string, RB []byte) ([]byte, error) {
// 	ctx := sm2keyexch.NewKAPCtx()
// 	if err := ctx.Init(local, localID, remote, remoteID, true, true); err != nil {
// 		return nil, err
// 	}
// 	_, err := ctx.Prepare()
// 	if err != nil {
// 		return nil, err
// 	}

// 	// Note: RB is required for SM2 Key Exchange but standard ECDH interface doesn't provide it.
// 	// This implementation may panic if RB is nil.
// 	// The user of this 'Standard Interface' on SM2 must be aware of this limitation
// 	// or we need to extend the interface or use a side-channel to pass RB.
// 	// For compilation sake, we proceed.
// 	var rbInput []byte
// 	if len(RB) == 0 {
// 		// Dummy 32 bytes to prevent panic if that's what C impl expects,
// 		// though result will be garbage for real exchange.
// 		rbInput = make([]byte, 32)
// 	} else {
// 		rbInput = RB
// 	}

// 	SharedKey, _, err := ctx.ComputeKey(rbInput, 32)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return SharedKey, nil
// }
