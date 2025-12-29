package ecdh_curve

import (
	"crypto"
	"io"
)

// 要求，实现了 ecdh.Cureve 的曲线，一定也实现了我这个接口

type Curve interface {
	GenerateKey(rand io.Reader) (PrivateKey, error)

	NewPrivateKey(key []byte) (PrivateKey, error)

	NewPublicKey(key []byte) (PublicKey, error)

	ecdh(local PrivateKey, remote PublicKey) ([]byte, error)
}

// *ecdh.PrivateKey 实现了这个接口
// sm2PriveteKey 也实现了这个接口
type PrivateKey interface {
	Equal(x crypto.PrivateKey) bool
	Bytes() []byte
	Curve() Curve
	ECDH(remote PublicKey) ([]byte, error)
	PublicKey() PublicKey
	Public() crypto.PublicKey
}

// *ecdh.PublicKey 实现了这个接口
// sm2PublicKey 也实现了这个接口
type PublicKey interface {
	Equal(x crypto.PublicKey) bool
	Bytes() []byte
	Curve() Curve
}
