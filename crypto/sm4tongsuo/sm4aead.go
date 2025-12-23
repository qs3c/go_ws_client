package sm4tongsuo

import (
	"crypto/cipher"
	"errors"
	"fmt"

	"github.com/albert/ws_client/crypto"
)

// // 加密流程
// enc, _ := sm4.NewEncrypter(crypto.CipherModeGCM, key, iv)
// enc.SetAAD([]byte("metadata:user=123,time=2023-01-01"))  // 设置关联数据
// ciphertext, _ := enc.EncryptAll(plaintext)
// tag, _ := enc.GetTag()

// // 解密流程
// dec, _ := sm4.NewDecrypter(crypto.CipherModeGCM, key, iv)
// dec.SetAAD([]byte("metadata:user=123,time=2023-01-01"))  // 设置相同的关联数据
// dec.SetTag(tag)
// plaintext, _ := dec.DecryptAll(ciphertext)

// 基于 sm4Encrypter 和 sm4Decrypter 实现 aead 接口 【其实不实现也可以的】

type AEAD interface {
	cipher.AEAD

	// explicitNonceLen returns the number of bytes of explicit nonce
	// included in each record. This is eight for older AEADs and
	// zero for modern ones.
	ExplicitNonceLen() int
}

func NewSm4AEADCipher(key, iv []byte, isEncrypt bool) cipher.AEAD {
	if isEncrypt {
		return NewSm4AEADEncrypter(key, iv)
	}
	return NewSm4AEADDecrypter(key, iv)
}

type sm4AEADEncrypter struct {
	enc *sm4Encrypter
}

func NewSm4AEADEncrypter(key, iv []byte) *sm4AEADEncrypter {
	enc, err := NewEncrypter(crypto.CipherModeGCM, key, iv)
	if err != nil {
		fmt.Printf("sm4AEADEncrypter NewSm4AEADEncrypter error [NewEncrypter]: %v", err)
		return nil
	}
	return &sm4AEADEncrypter{
		enc: enc,
	}
}

func (e *sm4AEADEncrypter) Seal(dst, nonce, plaintext, aad []byte) []byte {
	// 设置 AAD
	e.enc.SetAAD(aad)
	// 加密
	ciphertext, err := e.enc.EncryptAll(plaintext)
	if err != nil {
		fmt.Printf("sm4AEADEncrypter Seal error [EncryptAll]: %v", err)
		return nil
	}
	// 获取 tag
	tag, err := e.enc.GetTag()
	if err != nil {
		fmt.Printf("sm4AEADEncrypter Seal error [GetTag]: %v", err)
		return nil
	}

	ciphertext = append(ciphertext, tag...)
	dst = append(dst, ciphertext...)
	return dst
}

func (e *sm4AEADEncrypter) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	fmt.Printf("sm4AEADEncrypter do not implement Open method")
	return nil, errors.New("sm4AEADEncrypter do not implement Open method")
}

// 返回 nonce 长度（也就是 iv 长度）
// 其实设计意图是返回：使用该 AEAD 接口时需要提供的nonce长度，而不是返回当前的 Nonce 长度
// 一般GCM中是12，有的里面前4字节是固定的，只需提供8字节变化的
func (e *sm4AEADEncrypter) NonceSize() int {
	// return len(e.enc.iv)
	return 12
}

// 返回 tag 长度 GCM 是 16
func (e *sm4AEADEncrypter) Overhead() int {
	return 16
}

// 返回需要显示传输的 nonce 长度
func (e *sm4AEADEncrypter) ExplicitNonceLen() int {
	// 如果没有使用特别的技术，需要显示传输的 nonce 长度就是原本的 iv 长度
	return e.NonceSize()
}

type sm4AEADDecrypter struct {
	dec *sm4Decrypter
}

func NewSm4AEADDecrypter(key, iv []byte) *sm4AEADDecrypter {
	dec, err := NewDecrypter(crypto.CipherModeGCM, key, iv)
	if err != nil {
		fmt.Printf("sm4AEADDecrypter NewSm4AEADDecrypter error [NewDecrypter]: %v", err)
		return nil
	}
	return &sm4AEADDecrypter{
		dec: dec,
	}
}

func (e *sm4AEADDecrypter) Open(dst, nonce, ciphertext, aad []byte) ([]byte, error) {
	// 设置 AAD
	e.dec.SetAAD(aad)
	tag := ciphertext[len(ciphertext)-e.Overhead():]

	// 设置 tag
	e.dec.SetTag(tag)

	// 解密
	plaintext, err := e.dec.DecryptAll(ciphertext[:len(ciphertext)-e.Overhead()])
	if err != nil {
		fmt.Printf("sm4AEADDecrypter Open error [DecryptAll]: %v", err)
		return nil, err
	}

	return plaintext, nil
}

func (e *sm4AEADDecrypter) Seal(dst, nonce, plaintext, aad []byte) []byte {
	fmt.Printf("sm4AEADDecrypter do not implement Seal method")
	return nil
}

func (e *sm4AEADDecrypter) NonceSize() int {
	return 12
}

func (e *sm4AEADDecrypter) Overhead() int {
	// 目前是只有 GCM 后续可根据 GCM 或 CCM 做区分
	return 16
}

func (e *sm4AEADDecrypter) explicitNonceLen() int {
	return e.NonceSize()
}
