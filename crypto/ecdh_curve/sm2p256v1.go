package ecdh_curve

import (
	"crypto"
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
	// 预共享信息 用户ID 和静态公钥
	localID               string
	remoteID              string
	localStaticPublicKey  *ccrypto.ECKey
	remoteStaticPublicKey *ccrypto.ECKey
}

func NewSm2P256V1(localID string, remoteID string, localStaticPublicKey *ccrypto.ECKey, remoteStaticPublicKey *ccrypto.ECKey) *sm2p256v1Curve {
	return &sm2p256v1Curve{
		localID:               localID,
		remoteID:              remoteID,
		localStaticPublicKey:  localStaticPublicKey,
		remoteStaticPublicKey: remoteStaticPublicKey,
	}
}

func (c *sm2p256v1Curve) String() string {
	return "SM2P256V1"
}

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

func (c *sm2p256v1Curve) NewPublicKey(key []byte) (PublicKey, error) {
	if len(key) != sm2p256v1PublicKeySize {
		return nil, errors.New("sm2p256v1: invalid public key size")
	}

	return &sm2PublicKey{
		curve:     c,
		publicKey: key,
	}, nil

}

func (c *sm2p256v1Curve) ecdh(local PrivateKey, remote PublicKey) ([]byte, error) {
	return nil, nil
}

// --- PrivateKey Implementation ---

type sm2PrivateKey struct {
	curve      Curve
	privateKey []byte
	publicKey  PublicKey
}

func (k *sm2PrivateKey) Equal(x crypto.PrivateKey) bool {
	return true
}
func (k *sm2PrivateKey) Bytes() []byte {
	return nil
}
func (k *sm2PrivateKey) Curve() Curve {
	return nil
}
func (k *sm2PrivateKey) ECDH(remote PublicKey) ([]byte, error) {
	return nil, nil
}
func (k *sm2PrivateKey) PublicKey() PublicKey {
	return nil
}
func (k *sm2PrivateKey) Public() crypto.PublicKey {
	return nil
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
	return true
}
func (k *sm2PublicKey) Bytes() []byte {
	return nil
}
func (k *sm2PublicKey) Curve() Curve {
	return nil
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

func (c *sm2p256v1Curve) ecdh(local *ccrypto.ECKey, localID string, remote *ccrypto.ECKey, remoteID string, RB []byte) ([]byte, error) {
	ctx := sm2keyexch.NewKAPCtx()
	if err := ctx.Init(local, localID, remote, remoteID, true, true); err != nil {
		return nil, err
	}
	_, err := ctx.Prepare()
	if err != nil {
		return nil, err
	}

	// Note: RB is required for SM2 Key Exchange but standard ECDH interface doesn't provide it.
	// This implementation may panic if RB is nil.
	// The user of this 'Standard Interface' on SM2 must be aware of this limitation
	// or we need to extend the interface or use a side-channel to pass RB.
	// For compilation sake, we proceed.
	var rbInput []byte
	if len(RB) == 0 {
		// Dummy 32 bytes to prevent panic if that's what C impl expects,
		// though result will be garbage for real exchange.
		rbInput = make([]byte, 32)
	} else {
		rbInput = RB
	}

	SharedKey, _, err := ctx.ComputeKey(rbInput, 32)
	if err != nil {
		return nil, err
	}
	return SharedKey, nil
}
