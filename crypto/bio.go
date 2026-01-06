package crypto

/*
#cgo CFLAGS: -IE:/Tongsuo-8.3-stable/include -DOPENSSL_API_COMPAT=0x10100000L
#cgo LDFLAGS: -LE:/Tongsuo-8.3-stable -lcrypto -lssl
#include "myshim.h"
#include <openssl/bio.h>
#include "shim.h"

// OpenSSL 1.1+ makes BIO opaque. We define a dummy struct so CGO
// can determine a size and generating the type.
struct bio_st {
    int dummy;
};
*/

// import "C"

// import (
// 	"fmt"
// 	"io"
// 	"unsafe"
// )

// type anyBio C.BIO

// // 将 OpenSSL 的 C BIO 对象指针转换为 Go 中定义的 anyBio 类型指针
// // 本质上是一种 unsafe 操作，但被封装在函数中以提高代码可读性和安全性
// func asAnyBio(b *C.BIO) *anyBio { return (*anyBio)(b) }

// func (bio *anyBio) Read(buf []byte) (int, error) {
// 	if len(buf) == 0 {
// 		return 0, nil
// 	}
// 	n := int(C.X_BIO_read((*C.BIO)(bio), unsafe.Pointer(&buf[0]), C.int(len(buf))))
// 	if n <= 0 {
// 		return 0, io.EOF
// 	}
// 	return n, nil
// }

// func (bio *anyBio) Write(buf []byte) (int, error) {
// 	if len(buf) == 0 {
// 		return 0, nil
// 	}
// 	ret := int(C.X_BIO_write((*C.BIO)(bio), unsafe.Pointer(&buf[0]),
// 		C.int(len(buf))))
// 	if ret < 0 {
// 		return 0, fmt.Errorf("BIO write failed: %w", PopError())
// 	}
// 	if ret < len(buf) {
// 		return ret, fmt.Errorf("BIO write trucated: %w", ErrPartialWrite)
// 	}
// 	return ret, nil
// }
