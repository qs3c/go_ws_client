package crypto

/*
#cgo CFLAGS: -DOPENSSL_API_COMPAT=0x10100000L
#cgo LDFLAGS: -lcrypto -lssl
#include "myshim.h"
#include "shim.h"
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <stdlib.h>

*/
import "C"

import (
	"sync"
	"unsafe"
)

// mapping 是一个映射表
// 用于存储和管理 C BIO 到 GO BIO 的映射关系：unsafe.Pointer → unsafe.Pointer
type mapping struct {
	lock   sync.Mutex
	values map[token]unsafe.Pointer
}

func newMapping() *mapping {
	return &mapping{
		values: make(map[token]unsafe.Pointer),
	}
}

type token unsafe.Pointer

func (m *mapping) Add(x unsafe.Pointer) token {
	// 新分配的 1 字节内存空间的地址作为 token
	res := token(C.malloc(1))

	m.lock.Lock()
	m.values[res] = x
	m.lock.Unlock()

	// 随机生成 token 设置映射表后返回了 token
	// 用于在 MakeCBIO 中设置 token 到 C BIO 中
	return res
}

// 根据 token 获取对应的 Go BIO 地址【其实就是就 C BIO 对应的 GO BIO 地址】
func (m *mapping) Get(x token) unsafe.Pointer {
	m.lock.Lock()
	res := m.values[x]
	m.lock.Unlock()

	return res
}

func (m *mapping) Del(x token) {
	m.lock.Lock()
	delete(m.values, x)
	m.lock.Unlock()

	// 释放 token 指向的内存
	C.free(unsafe.Pointer(x))
}
