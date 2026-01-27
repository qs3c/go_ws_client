package sm2keyexch


/*
#cgo CFLAGS: -I${SRCDIR}/../../third_party/tongsuo/include -DOPENSSL_API_COMPAT=0x10100000L
#cgo LDFLAGS: -L${SRCDIR}/../../third_party/tongsuo -L${SRCDIR}/../../third_party/tongsuo/lib -lkeyexchange -lcrypto -lssl
#include "keyexchange.h"
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <stdlib.h>
*/
import "C"

import (
	"errors"
	"unsafe"

	"github.com/albert/ws_client/crypto"
)

type KAPCtx struct{ c C.SM2_KAP_CTX }

func NewKAPCtx() *KAPCtx {
	var ctx KAPCtx
	C.memset(unsafe.Pointer(&ctx.c), 0, C.size_t(unsafe.Sizeof(ctx.c)))
	return &ctx
}

func (x *KAPCtx) Init(local *crypto.ECKey, id string, remotePub *crypto.ECKey, rid string, initiator bool, doChecksum bool) error {
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
	if C.SM2_KAP_CTX_init(&x.c, (*C.EC_KEY)(local.UnsafePtr()), cid, C.size_t(len(id)), (*C.EC_KEY)(remotePub.UnsafePtr()), crid, C.size_t(len(rid)), ini, chk) == 0 {
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