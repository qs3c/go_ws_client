//go:build ignore

package e2ewebsocket

import "crypto/cipher"

// 这个文件后面要删掉，在e2ewebsocket包中定义加密模式接口是不合理的
// 要么就不要，要么就做到自定义的crypto包下去

type cbcMode interface {
	cipher.BlockMode
	SetIV([]byte)
}

type aead interface {
	cipher.AEAD
	explicitNonceLen() int
}
