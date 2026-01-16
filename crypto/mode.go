package crypto

import "crypto/cipher"

type AEAD interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	ExplicitNonceLen() int
}

type CBCMode interface {
	cipher.BlockMode
	SetIV([]byte)
}
