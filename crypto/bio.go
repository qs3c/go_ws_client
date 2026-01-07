package crypto

/*
#cgo CFLAGS: -IE:/Tongsuo-8.3-stable/include -DOPENSSL_API_COMPAT=0x10100000L
#cgo LDFLAGS: -LE:/Tongsuo-8.3-stable -lcrypto -lssl
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
	"fmt"
	"io"
	"sync"
	"unsafe"
)

const (
	SSLRecordSize = 16 * 1024
)

func nonCopyGoBytes(ptr uintptr, length int) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(ptr)), length)
}

func nonCopyCString(data *C.char, size C.int) []byte {
	return nonCopyGoBytes(uintptr(unsafe.Pointer(data)), int(size))
}

// 映射表
var writeBioMapping = newMapping()

type WriteBio struct {
	dataMtx        sync.Mutex
	opMtx          sync.Mutex
	buf            []byte
	releaseBuffers bool
}

func loadWritePtr(b *C.BIO) *WriteBio {
	// 从 C BIO 中获取 token
	t := token(C.X_BIO_get_data(b))

	// 从 WriteBio 映射表获取对应的 GO WriteBio 地址
	return (*WriteBio)(writeBioMapping.Get(t))
}

// 处理 OpenSSL BIO 对象状态的一个重要辅助函数。
// 它清除特定的重试标志
// 确保 BIO 对象在成功执行 IO 操作后能够正确重置状态,从而维持正常的IO操作流程

// 通常在成功执行 IO 操作后，需要重置 BIO 状态时调用
func bioClearRetryFlags(b *C.BIO) {
	C.X_BIO_clear_flags(b, C.BIO_FLAGS_RWS|C.BIO_FLAGS_SHOULD_RETRY)
}

// 当没有可读数据时，用于通知调用者稍后重试读取操作
func bioSetRetryRead(b *C.BIO) {
	C.X_BIO_set_flags(b, C.BIO_FLAGS_READ|C.BIO_FLAGS_SHOULD_RETRY)
}

// C 语言 OpenSSL BIO 系统与 Go 语言内存缓冲区之间的数据写入桥梁
// C 语言可调用的导出函数

//export go_write_bio_write
func go_write_bio_write(bio *C.BIO, data *C.char, size C.int) C.int {
	var rc C.int

	defer func() {
		if err := recover(); err != nil {
			// logger.Critf("openssl: writeBioWrite panic'd: %v", err)
			rc = -1
		}
	}()
	// 从 C BIO 中获取 GO WriteBio 指针
	ptr := loadWritePtr(bio)
	if ptr == nil || data == nil || size < 0 {
		return -1
	}

	// 上 GO WriteBio 数据锁
	ptr.dataMtx.Lock()
	defer ptr.dataMtx.Unlock()

	// 重置 C BIO 状态，清除重试标志
	bioClearRetryFlags(bio)
	// 把 C BIO 的数据转化为 Go 字节切片追加到 GO WriteBio 的缓冲区
	ptr.buf = append(ptr.buf, nonCopyCString(data, size)...)
	rc = size

	return rc
}

//export go_write_bio_ctrl
func go_write_bio_ctrl(bio *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) C.long {
	_, _ = arg1, arg2 // unused

	var rc C.long

	// 使用 defer 和 recover 捕获潜在的 panic，防止Go panic传播到 C 代码
	// 发生 panic 时返回 -1
	defer func() {
		if err := recover(); err != nil {
			// logger.Critf("openssl: writeBioCtrl panic'd: %v", err)
			rc = -1
		}
	}()

	switch cmd {

	// 查询 BIO 中待处理（待写入）的数据量，调用 writeBioPending 函数获取
	case C.BIO_CTRL_WPENDING:
		rc = writeBioPending(bio)
	// 处理 BIO_CTRL_DUP 和 BIO_CTRL_FLUSH 命令，返回 1 表示成功
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		rc = 1
	default:
		rc = 0
	}

	return rc
}

// 从 Write 映射表中获取当前 C BIO 对应的 WriteBio 结构体指针
// 上数据锁后读取当前 WriteBio buf 的长度
func writeBioPending(b *C.BIO) C.long {
	ptr := loadWritePtr(b)
	if ptr == nil {
		return 0
	}
	ptr.dataMtx.Lock()
	defer ptr.dataMtx.Unlock()

	return C.long(len(ptr.buf))
}

// 将 WriteBio buf 中的数据写入 net.Conn
func (bio *WriteBio) WriteTo(writer io.Writer) (int64, error) {
	// 上操作锁
	bio.opMtx.Lock()
	defer bio.opMtx.Unlock()

	// write whatever data we currently have
	// 上数据锁取数据
	bio.dataMtx.Lock()
	data := bio.buf
	bio.dataMtx.Unlock()

	if len(data) == 0 {
		// 当前没有数据，直接返回
		return 0, nil
	}

	n, err := writer.Write(data)

	// subtract however much data we wrote from the buffer
	bio.dataMtx.Lock()
	// 从 buf 中删除已写入的数据
	// 也就是将未写入的数据前移，并更新 buf 长度
	bio.buf = bio.buf[:copy(bio.buf, bio.buf[n:])]
	// 如果已经全部写入，且设置了释放缓冲区标志
	// 则将 buf 置为 nil
	if bio.releaseBuffers && len(bio.buf) == 0 {
		bio.buf = nil
	}
	bio.dataMtx.Unlock()

	return int64(n), err
}

// 设置 WriteBio 的释放缓冲区标志
func (bio *WriteBio) SetRelease(flag bool) {
	bio.dataMtx.Lock()
	defer bio.dataMtx.Unlock()
	bio.releaseBuffers = flag
}

func (bio *WriteBio) Disconnect(b *C.BIO) {
	if loadWritePtr(b) == bio {
		// 如果传入的 C BIO 与当前 WriteBio 匹配
		// 则从 WriteBio 映射表中删除该映射关系
		writeBioMapping.Del(token(C.X_BIO_get_data(b)))
		// 也从 C BIO 中删除 token
		C.X_BIO_set_data(b, nil)
	}
}

func (bio *WriteBio) MakeCBIO() *C.BIO {
	// 创建C BIO
	rv := C.X_BIO_new_write_bio()
	// 加入 Write 映射表
	token := writeBioMapping.Add(unsafe.Pointer(bio))
	// 并把 token 设置到 C BIO 上
	C.X_BIO_set_data(rv, unsafe.Pointer(token))

	return rv
}

var readBioMapping = newMapping()

type ReadBio struct {
	dataMtx        sync.Mutex
	opMtx          sync.Mutex
	buf            []byte
	eof            bool
	releaseBuffers bool
}

// 从 C BIO 中获取当前 ReadBio 结构体指针
func loadReadPtr(b *C.BIO) *ReadBio {
	return (*ReadBio)(readBioMapping.Get(token(C.X_BIO_get_data(b))))
}

// 当 OpenSSL 需要从 Go 实现的 ReadBio 对象中读取数据时会调用此函数

//export go_read_bio_read
func go_read_bio_read(bio *C.BIO, data *C.char, size C.int) C.int {
	rc := 0

	defer func() {
		if err := recover(); err != nil {
			// logger.Critf("openssl: go_read_bio_read panic'd: %v", err)
			rc = -1
		}
	}()

	ptr := loadReadPtr(bio)
	if ptr == nil || size < 0 {
		return -1
	}

	ptr.dataMtx.Lock()
	defer ptr.dataMtx.Unlock()

	// 清除重试标记
	bioClearRetryFlags(bio)

	if len(ptr.buf) == 0 {
		// 如果 buf 中没有数据，并且 eof 标志为 true
		// 则返回 0 表示已没有数据可读
		if ptr.eof {
			return 0
		}
		// 如果 buf 中没有数据，且 eof 标志为 false
		// 则设置重试读取标志并返回 -1
		// 表示需要等待数据来了再读
		bioSetRetryRead(bio)
		return -1
	}
	// 当请求读取 0 字节或目标缓冲区为 nil 时
	// 返回当前可用数据量而不进行实际读取
	if size == 0 || data == nil {
		return C.int(len(ptr.buf))
	}
	// 创建指向 C 缓冲区的 Go 切片视图
	// 将数据从 Go ReadBio 缓冲区复制到 C 缓冲区的 Go 切片视图中
	rc = copy(nonCopyCString(data, size), ptr.buf)
	// 从 Go ReadBio 缓冲区中删除已读取的数据
	// 把未读取的数据前移，并把后面多余的截掉
	ptr.buf = ptr.buf[:copy(ptr.buf, ptr.buf[rc:])]
	// 如果允许 release 并且 ReadBio 的 buf 被读空了
	// 就设置 buf 为 nil
	if ptr.releaseBuffers && len(ptr.buf) == 0 {
		ptr.buf = nil
	}
	return C.int(rc)
}

//export go_read_bio_ctrl
func go_read_bio_ctrl(bio *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) C.long {
	_, _ = arg1, arg2 // unused

	var rc C.long
	defer func() {
		if err := recover(); err != nil {
			// logger.Critf("openssl: readBioCtrl panic'd: %v", err)
			rc = -1
		}
	}()

	switch cmd {
	// 获取 Go ReadBio 剩余数据的长度
	case C.BIO_CTRL_PENDING:
		rc = readBioPending(bio)
	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
		rc = 1
	default:
		rc = 0
	}

	return rc
}

// 当前 Go 中的 ReadBio 结构体的 buf 字段中待处理（待读取）的数据量
func readBioPending(b *C.BIO) C.long {
	// 从 Read 映射表中获取当前 C BIO 对应的 ReadBio 结构体指针
	ptr := loadReadPtr(b)
	if ptr == nil {
		return 0
	}
	// 上 data 锁并获取 ReadBio buf 的长度
	ptr.dataMtx.Lock()
	defer ptr.dataMtx.Unlock()
	return C.long(len(ptr.buf))
}

func (bio *ReadBio) SetRelease(flag bool) {
	bio.dataMtx.Lock()
	defer bio.dataMtx.Unlock()
	bio.releaseBuffers = flag
}

func (bio *ReadBio) ReadFromOnce(r io.Reader) (int, error) {
	bio.opMtx.Lock()
	defer bio.opMtx.Unlock()

	// make sure we have a destination that fits at least one SSL record
	bio.dataMtx.Lock()
	if cap(bio.buf) < len(bio.buf)+SSLRecordSize {
		newBuf := make([]byte, len(bio.buf), len(bio.buf)+SSLRecordSize)
		copy(newBuf, bio.buf)
		bio.buf = newBuf
	}

	dst := bio.buf[len(bio.buf):cap(bio.buf)]
	dstSlice := bio.buf
	bio.dataMtx.Unlock()

	n, err := r.Read(dst)
	bio.dataMtx.Lock()
	defer bio.dataMtx.Unlock()
	if n > 0 {
		if len(dstSlice) != len(bio.buf) {
			// someone shrunk the buffer, so we read in too far ahead and we
			// need to slide backwards
			copy(bio.buf[len(bio.buf):len(bio.buf)+n], dst)
		}
		bio.buf = bio.buf[:len(bio.buf)+n]
	}

	if err != nil {
		return n, fmt.Errorf("read from once error: %w", err)
	}

	return n, nil
}

func (bio *ReadBio) MakeCBIO() *C.BIO {
	rv := C.X_BIO_new_read_bio()
	token := readBioMapping.Add(unsafe.Pointer(bio))
	C.X_BIO_set_data(rv, unsafe.Pointer(token))
	return rv
}

func (bio *ReadBio) Disconnect(b *C.BIO) {
	if loadReadPtr(b) == bio {
		readBioMapping.Del(token(C.X_BIO_get_data(b)))
		C.X_BIO_set_data(b, nil)
	}
}

// 标记 Go ReadBio 结构体的 eof 标志为 true
// 表示后续读取操作将返回 0 表示已没有数据可读
func (bio *ReadBio) MarkEOF() {
	bio.dataMtx.Lock()
	defer bio.dataMtx.Unlock()
	bio.eof = true
}

type anyBio C.BIO

// 将 OpenSSL 的 C BIO 对象指针转换为 Go 中定义的 anyBio 类型指针
// 本质上是一种 unsafe 操作，但被封装在函数中以提高代码可读性和安全性
func asAnyBio(b *C.BIO) *anyBio { return (*anyBio)(b) }

func (bio *anyBio) Read(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	n := int(C.X_BIO_read((*C.BIO)(bio), unsafe.Pointer(&buf[0]), C.int(len(buf))))
	if n <= 0 {
		return 0, io.EOF
	}
	return n, nil
}

func (bio *anyBio) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	ret := int(C.X_BIO_write((*C.BIO)(bio), unsafe.Pointer(&buf[0]),
		C.int(len(buf))))
	if ret < 0 {
		return 0, fmt.Errorf("BIO write failed: %w", PopError())
	}
	if ret < len(buf) {
		return ret, fmt.Errorf("BIO write trucated: %w", ErrPartialWrite)
	}
	return ret, nil
}
