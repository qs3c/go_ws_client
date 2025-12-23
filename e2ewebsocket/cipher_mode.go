package e2ewebsocket

import "crypto/cipher"

type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

type aead interface {
	cipher.AEAD
	explicitNonceLen() int
}
