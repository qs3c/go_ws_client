package sm2keyexch

// sm2 密钥交换依赖的是安装好的E盘的 8.3 铜锁库

/*
#cgo CFLAGS: -IE:/Tongsuo-8.3-stable/include -DOPENSSL_API_COMPAT=0x10100000L
#cgo LDFLAGS: -LE:/Tongsuo-8.3-stable -lkeyexchange -lcrypto -lssl
#include "keyexchange.h"
*/
import "C"

import (
	"errors"
	"unsafe"
)

type ECKey struct{ ptr *C.EC_KEY }

func NewECKeySM2() (*ECKey, error) {
	k := C.EC_KEY_new_by_curve_name(C.NID_sm2)
	if k == nil {
		return nil, errors.New("EC_KEY_new_by_curve_name failed")
	}
	return &ECKey{ptr: k}, nil
}

func (k *ECKey) Generate() error {
	if C.EC_KEY_generate_key(k.ptr) == 0 {
		return errors.New("EC_KEY_generate_key failed")
	}
	return nil
}

func (k *ECKey) SetPublicFrom(src *ECKey) error {
	if C.EC_KEY_set_public_key(k.ptr, C.EC_KEY_get0_public_key(src.ptr)) == 0 {
		return errors.New("EC_KEY_set_public_key failed")
	}
	return nil
}

func (k *ECKey) Free() {
	if k.ptr != nil {
		C.EC_KEY_free(k.ptr)
		k.ptr = nil
	}
}

type KAPCtx struct{ c C.SM2_KAP_CTX }

func NewKAPCtx() *KAPCtx {
	var ctx KAPCtx
	C.memset(unsafe.Pointer(&ctx.c), 0, C.size_t(unsafe.Sizeof(ctx.c)))
	return &ctx
}

func (x *KAPCtx) Init(local *ECKey, id string, remotePub *ECKey, rid string, initiator bool, doChecksum bool) error {
	cid := C.CString(id)
	crid := C.CString(rid)
	defer C.free(unsafe.Pointer(cid))
	defer C.free(unsafe.Pointer(crid))
	ini := C.int(0)
	chk := C.int(0)
	if initiator {
		ini = 1
	}
	if doChecksum {
		chk = 1
	}
	if C.SM2_KAP_CTX_init(&x.c, local.ptr, cid, C.size_t(len(id)), remotePub.ptr, crid, C.size_t(len(rid)), ini, chk) == 0 {
		return errors.New("SM2_KAP_CTX_init failed")
	}
	return nil
}

func (x *KAPCtx) Prepare() ([]byte, error) {
	buf := make([]byte, 100)
	l := C.size_t(len(buf))
	if C.SM2_KAP_prepare(&x.c, (*C.uchar)(unsafe.Pointer(&buf[0])), &l) == 0 {
		return nil, errors.New("SM2_KAP_prepare failed")
	}
	return buf[:l], nil
}

func (x *KAPCtx) FinalCheck(checksum []byte) error {
	if C.SM2_KAP_final_check(&x.c, (*C.uchar)(unsafe.Pointer(&checksum[0])), C.size_t(len(checksum))) == 0 {
		return errors.New("SM2_KAP_final_check failed")
	}
	return nil
}

func (x *KAPCtx) Cleanup() {
	C.SM2_KAP_CTX_cleanup(&x.c)
}

func (x *KAPCtx) ComputeKey(remotePoint []byte, keyLen int) ([]byte, []byte, error) {
	key := make([]byte, keyLen)
	cs := make([]byte, 64)
	var csl C.size_t
	if C.SM2_KAP_compute_key(&x.c,
		(*C.uchar)(unsafe.Pointer(&remotePoint[0])), C.size_t(len(remotePoint)),
		(*C.uchar)(unsafe.Pointer(&key[0])), C.size_t(len(key)),
		(*C.uchar)(unsafe.Pointer(&cs[0])), &csl) == 0 {
		return nil, nil, errors.New("SM2_KAP_compute_key failed")
	}
	return key, cs[:csl], nil
}
