package sm3tongsuo

/*
#cgo CFLAGS: -I${SRCDIR}/../../third_party/tongsuo-install/include -DOPENSSL_API_COMPAT=0x10100000L
#cgo LDFLAGS: -L${SRCDIR}/../../third_party/tongsuo-install -L${SRCDIR}/../../third_party/tongsuo-install/lib
#include "../myshim.h"
*/
import "C"

import (
	// "crypto"
	"crypto"
	"errors"
	"fmt"
	"hash"
	"runtime"
	"unsafe"
	// ccrypto "github.com/qs3c/e2e-secure-ws/crypto"
)

// 封闭式的你注册不进去
// func init() {
// 	crypto.RegisterHash(ccrypto.SM3, NewSM3)
// }

const (
	SM3HASH crypto.Hash = 50
)

const (
	MDSize    = 32
	sm3Cblock = 64
)

var _ hash.Hash = new(SM3)

type SM3 struct {
	ctx *C.EVP_MD_CTX
}

func NewSM3() hash.Hash {
	sm3Hash, err := New()
	if err != nil {
		return nil
	}
	return sm3Hash
}

func New() (*SM3, error) {
	hash := &SM3{ctx: nil}
	hash.ctx = C.EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, fmt.Errorf("failed to create md ctx: %w", errors.New("ErrMallocFailure"))
	}
	runtime.SetFinalizer(hash, func(hash *SM3) { hash.Close() })
	hash.Reset()

	return hash, nil
}

func (s *SM3) BlockSize() int {
	return sm3Cblock
}

func (s *SM3) Size() int {
	return MDSize
}

func (s *SM3) Close() {
	if s.ctx != nil {
		C.EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *SM3) Reset() {
	C.EVP_DigestInit_ex(s.ctx, C.EVP_sm3(), nil)
}

func (s *SM3) Write(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	if C.EVP_DigestUpdate(s.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
		return 0, fmt.Errorf("failed to update digest: %w", errors.New("ErrUpdateFailure"))
	}
	return len(data), nil
}

func (s *SM3) Sum(in []byte) []byte {
	hash, err := New()
	if err != nil {
		panic("NewSM3 fail " + err.Error())
	}

	if C.EVP_MD_CTX_copy_ex(hash.ctx, s.ctx) == 0 {
		panic("NewSM3 EVP_MD_CTX_copy_ex fail")
	}

	result := hash.checkSum()
	return append(in, result[:]...)
}

func (s *SM3) checkSum() [MDSize]byte {
	var result [MDSize]byte

	C.EVP_DigestFinal_ex(s.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), nil)

	return result
}

func Sum(data []byte) [MDSize]byte {
	var result [MDSize]byte

	C.EVP_Digest(unsafe.Pointer(&data[0]), C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&result[0])), nil, C.EVP_sm3(), nil)

	return result
}
