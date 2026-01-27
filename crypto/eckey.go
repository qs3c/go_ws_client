package crypto

/*
#cgo CFLAGS: -DOPENSSL_API_COMPAT=0x10100000L
#cgo LDFLAGS: -lkeyexchange -lcrypto -lssl
#include "./sm2keyexch/keyexchange.h"
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"unsafe"
)

type ECKey struct{ ptr *C.EC_KEY }

// 产生空的 SM2 ECKey
func NewECKeySM2() (*ECKey, error) {
	k := C.EC_KEY_new_by_curve_name(C.NID_sm2)
	if k == nil {
		return nil, errors.New("EC_KEY_new_by_curve_name failed")
	}
	return &ECKey{ptr: k}, nil
}

func (k *ECKey) UnsafePtr() unsafe.Pointer {
	return unsafe.Pointer(k.ptr)
}

// 在空 ECKey 中填入新生成的公私钥对
func (k *ECKey) Generate() error {
	if C.EC_KEY_generate_key(k.ptr) == 0 {
		return errors.New("EC_KEY_generate_key failed")
	}
	return nil
}

// 从一个包含公私钥的 ECKey 提取公钥到另一个新的 ECKey 中
func (k *ECKey) SetPublicFrom(src *ECKey) error {
	if C.EC_KEY_set_public_key(k.ptr, C.EC_KEY_get0_public_key(src.ptr)) == 0 {
		return errors.New("EC_KEY_set_public_key failed")
	}
	return nil
}

// 私钥序列化与反序列化 121 字节
func (k *ECKey) SerializePrivateKey() ([]byte, error) {
	if k.ptr == nil {
		return nil, errors.New("ECKey is nil")
	}
	l := C.i2d_ECPrivateKey(k.ptr, nil)
	if l <= 0 {
		return nil, errors.New("i2d_ECPrivateKey failed to get length")
	}

	cBuf := (*C.uchar)(C.malloc(C.size_t(l)))
	if cBuf == nil {
		return nil, errors.New("malloc failed")
	}
	defer C.free(unsafe.Pointer(cBuf))

	tmp := cBuf
	if C.i2d_ECPrivateKey(k.ptr, &tmp) <= 0 {
		return nil, errors.New("i2d_ECPrivateKey failed")
	}

	return C.GoBytes(unsafe.Pointer(cBuf), C.int(l)), nil
}

func NewECKeyFromPrivateKey(data []byte) (*ECKey, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	cBuf := C.CBytes(data)
	defer C.free(cBuf)

	p := (*C.uchar)(cBuf)
	k := C.d2i_ECPrivateKey(nil, &p, C.long(len(data)))
	if k == nil {
		return nil, errors.New("d2i_ECPrivateKey failed")
	}
	return &ECKey{ptr: k}, nil
}

// 公钥序列化与反序列化 91 字节
func (k *ECKey) SerializePublicKey() ([]byte, error) {
	if k.ptr == nil {
		return nil, errors.New("ECKey is nil")
	}
	l := C.i2d_EC_PUBKEY(k.ptr, nil)
	if l <= 0 {
		return nil, errors.New("i2d_EC_PUBKEY failed to get length")
	}

	cBuf := (*C.uchar)(C.malloc(C.size_t(l)))
	if cBuf == nil {
		return nil, errors.New("malloc failed")
	}
	defer C.free(unsafe.Pointer(cBuf))

	tmp := cBuf
	if C.i2d_EC_PUBKEY(k.ptr, &tmp) <= 0 {
		return nil, errors.New("i2d_EC_PUBKEY failed")
	}

	return C.GoBytes(unsafe.Pointer(cBuf), C.int(l)), nil
}

func NewECKeyFromPublicKey(data []byte) (*ECKey, error) {
	if len(data) == 0 {
		return nil, errors.New("empty data")
	}

	cBuf := C.CBytes(data)
	defer C.free(cBuf)

	p := (*C.uchar)(cBuf)
	k := C.d2i_EC_PUBKEY(nil, &p, C.long(len(data)))
	if k == nil {
		return nil, errors.New("d2i_EC_PUBKEY failed")
	}
	return &ECKey{ptr: k}, nil
}

// 释放 ECKey
func (k *ECKey) Free() {
	if k.ptr != nil {
		C.EC_KEY_free(k.ptr)
		k.ptr = nil
	}
}
