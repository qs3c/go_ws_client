package crypto

import (
	"crypto/ecdh"
	"io"
)

// KeyExchangeCurve defines a unified interface for ECDH curves,
// heavily inspired by crypto/ecdh but made public to allow custom implementations (like SM2).
type KeyExchangeCurve interface {
	// GenerateKey generates a random PrivateKey.
	GenerateKey(rand io.Reader) (PrivateKey, error)

	// NewPrivateKey checks that key is valid and returns a PrivateKey.
	NewPrivateKey(key []byte) (PrivateKey, error)

	// NewPublicKey checks that key is valid and returns a PublicKey.
	NewPublicKey(key []byte) (PublicKey, error)

	// String returns the curve name.
	String() string
}

// PrivateKey is the interface for an ECDH private key.
type PrivateKey interface {
	// ECDH performs a Diffie-Hellman key exchange with a remote public key.
	// The implementation must verify that the remote key is compatible.
	ECDH(remote PublicKey) ([]byte, error)

	// Equal reports whether x represents the same private key.
	Equal(x PrivateKey) bool

	// PublicKey returns the public key corresponding to p.
	PublicKey() PublicKey

	// Bytes returns a copy of the encoding of the private key.
	Bytes() []byte
}

// PublicKey is the interface for an ECDH public key.
type PublicKey interface {
	// Equal reports whether x represents the same public key.
	Equal(x PublicKey) bool

	// Bytes returns a copy of the encoding of the public key.
	Bytes() []byte
}

// --- Standard Library Adapter ---

type StdCurveAdapter struct {
	Curve ecdh.Curve
}

func (a *StdCurveAdapter) GenerateKey(rand io.Reader) (PrivateKey, error) {
	k, err := a.Curve.GenerateKey(rand)
	if err != nil {
		return nil, err
	}
	return &StdPrivateKeyAdapter{k}, nil
}

func (a *StdCurveAdapter) NewPrivateKey(key []byte) (PrivateKey, error) {
	k, err := a.Curve.NewPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &StdPrivateKeyAdapter{k}, nil
}

func (a *StdCurveAdapter) NewPublicKey(key []byte) (PublicKey, error) {
	k, err := a.Curve.NewPublicKey(key)
	if err != nil {
		return nil, err
	}
	return &StdPublicKeyAdapter{k}, nil
}

func (a *StdCurveAdapter) String() string {
	// There is no standard String() method on ecdh.Curve so we return a placeholder or use reflection if needed.
	// For now, just generic.
	return "StandardECDHCurve"
}

type StdPrivateKeyAdapter struct {
	k *ecdh.PrivateKey
}

func (p *StdPrivateKeyAdapter) ECDH(remote PublicKey) ([]byte, error) {
	r, ok := remote.(*StdPublicKeyAdapter)
	if !ok {
		// Try to see if it's compatible standard key
		return nil, io.ErrNoProgress // mismatch
	}
	return p.k.ECDH(r.k)
}

func (p *StdPrivateKeyAdapter) Equal(x PrivateKey) bool {
	other, ok := x.(*StdPrivateKeyAdapter)
	if !ok {
		return false
	}
	return p.k.Equal(other.k)
}

func (p *StdPrivateKeyAdapter) PublicKey() PublicKey {
	return &StdPublicKeyAdapter{p.k.PublicKey()}
}

func (p *StdPrivateKeyAdapter) Bytes() []byte {
	return p.k.Bytes()
}

type StdPublicKeyAdapter struct {
	k *ecdh.PublicKey
}

func (p *StdPublicKeyAdapter) Equal(x PublicKey) bool {
	other, ok := x.(*StdPublicKeyAdapter)
	if !ok {
		return false
	}
	return p.k.Equal(other.k)
}

func (p *StdPublicKeyAdapter) Bytes() []byte {
	return p.k.Bytes()
}
