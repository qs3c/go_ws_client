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
	"os"
	"runtime"
	"unsafe"
)

type Method *C.EVP_MD

func SHA1Method() Method {
	return C.X_EVP_sha1()
}

func SHA256Method() Method {
	return C.X_EVP_sha256()
}

func SHA512Method() Method {
	return C.X_EVP_sha512()
}

func SM3Method() Method {
	return C.X_EVP_sm3()
}

// Constants for the various key types.
// Mapping of name -> NID taken from openssl/evp.h
const (
	KeyTypeNone    = NidUndef
	KeyTypeRSA     = NidRsaEncryption
	KeyTypeRSA2    = NidRsa
	KeyTypeDSA     = NidDsa
	KeyTypeDSA1    = NidDsa2
	KeyTypeDSA2    = NidDsaWithSHA
	KeyTypeDSA3    = NidDsaWithSHA1
	KeyTypeDSA4    = NidDsaWithSHA12
	KeyTypeDH      = NidDhKeyAgreement
	KeyTypeDHX     = NidDhpublicnumber
	KeyTypeEC      = NidX962IdEcPublicKey
	KeyTypeHMAC    = NidHmac
	KeyTypeCMAC    = NidCmac
	KeyTypeTLS1PRF = NidTLS1Prf
	KeyTypeHKDF    = NidHkdf
	KeyTypeX25519  = NidX25519
	KeyTypeX448    = NidX448
	KeyTypeED25519 = NidEd25519
	KeyTypeED448   = NidEd448
	KeyTypeSM2     = NidSM2
)

// 提供两个核心功能：加密+验证签名；和若干转密钥文件功能；
type EVPPublicKey interface {
	// VerifyPKCS1v15 verifies the data signature using PKCS1.15
	VerifyPKCS1v15(method Method, data, sig []byte) error

	// Encrypt encrypts the data using SM2
	Encrypt(data []byte) ([]byte, error)

	// MarshalPKIXPublicKeyPEM converts the public key to PEM-encoded PKIX
	// format
	MarshalPKIXPublicKeyPEM() (pemBlock []byte, err error)

	// MarshalPKIXPublicKeyDER converts the public key to DER-encoded PKIX
	// format
	MarshalPKIXPublicKeyDER() (derBlock []byte, err error)

	// KeyType returns an identifier for what kind of key is represented by this
	// object.
	KeyType() NID

	// BaseType returns an identifier for what kind of key is represented
	// by this object.
	// Keys that share same algorithm but use different legacy formats
	// will have the same BaseType.
	//
	// For example, a key with a `KeyType() == KeyTypeRSA` and a key with a
	// `KeyType() == KeyTypeRSA2` would both have `BaseType() == KeyTypeRSA`.
	BaseType() NID

	EvpPKey() *C.EVP_PKEY
}

// 提供两个核心功能：解密+签名；和转公钥功能+若干转密钥文件功能；
type EVPPrivateKey interface {
	EVPPublicKey

	// Public return public key
	Public() EVPPublicKey

	// SignPKCS1v15 signs the data using PKCS1.15
	SignPKCS1v15(method Method, data []byte) ([]byte, error)

	// Decrypt decrypts the data using SM2
	Decrypt(data []byte) ([]byte, error)

	// MarshalPKCS1PrivateKeyPEM converts the private key to PEM-encoded PKCS1
	// format
	MarshalPKCS1PrivateKeyPEM() (pemBlock []byte, err error)

	// MarshalPKCS1PrivateKeyDER converts the private key to DER-encoded PKCS1
	// format
	MarshalPKCS1PrivateKeyDER() (derBlock []byte, err error)

	// MarshalPKCS8PrivateKeyPEM converts the private key to PEM-encoded PKCS8
	// format
	MarshalPKCS8PrivateKeyPEM() (pemBlock []byte, err error)
}

func SupportEd25519() bool {
	return C.X_ED25519_SUPPORT != 0
}

type pKey struct {
	key *C.EVP_PKEY
}

func (key *pKey) EvpPKey() *C.EVP_PKEY { return key.key }

func (key *pKey) KeyType() NID {
	return NID(C.EVP_PKEY_id(key.key))
}

func (key *pKey) BaseType() NID {
	return NID(C.EVP_PKEY_base_id(key.key))
}

func (key *pKey) Public() EVPPublicKey {
	// 先转成 DER 文件然后从中提取公钥
	der, err := key.MarshalPKIXPublicKeyDER()
	if err != nil {
		return nil
	}

	pub, err := LoadPublicKeyFromDER(der)
	if err != nil {
		return nil
	}

	return pub
}

// PKCS (Public-Key Cryptography Standards) #1 v1.5
func (key *pKey) SignPKCS1v15(method Method, data []byte) ([]byte, error) {
	ctx := C.X_EVP_MD_CTX_new()
	defer C.X_EVP_MD_CTX_free(ctx)

	if key.KeyType() == KeyTypeED25519 {
		// do ED specific one-shot sign
		if method != nil || len(data) == 0 {
			return nil, ErrNilParameter
		}

		if C.X_EVP_DigestSignInit(ctx, nil, nil, nil, key.key) != 1 {
			return nil, PopError()
		}

		var sigblen C.size_t = C.size_t(C.X_EVP_PKEY_size(key.key))
		sig := make([]byte, sigblen)

		if C.X_EVP_DigestSign(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &sigblen, (*C.uchar)(unsafe.Pointer(&data[0])),
			C.size_t(len(data))) != 1 {
			return nil, PopError()
		}

		return sig[:sigblen], nil
	}

	if C.X_EVP_DigestSignInit(ctx, nil, method, nil, key.key) != 1 {
		return nil, PopError()
	}

	if len(data) > 0 {
		if C.X_EVP_DigestSignUpdate(ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
			return nil, PopError()
		}
	}

	var sigblen C.size_t = C.size_t(C.X_EVP_PKEY_size(key.key))
	sig := make([]byte, sigblen)

	if C.X_EVP_DigestSignFinal(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &sigblen) != 1 {
		return nil, PopError()
	}

	return sig[:sigblen], nil
}

func (key *pKey) VerifyPKCS1v15(method Method, data, sig []byte) error {
	ctx := C.X_EVP_MD_CTX_new()
	defer C.X_EVP_MD_CTX_free(ctx)

	if key.KeyType() == KeyTypeED25519 {
		// do ED specific one-shot sign

		if method != nil || len(data) == 0 || len(sig) == 0 {
			return ErrNilParameter
		}

		if C.X_EVP_DigestVerifyInit(ctx, nil, nil, nil, key.key) != 1 {
			return PopError()
		}

		if C.X_EVP_DigestVerify(ctx, ((*C.uchar)(unsafe.Pointer(&sig[0]))), C.size_t(len(sig)),
			(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
			return PopError()
		}

		return nil
	}

	if C.X_EVP_DigestVerifyInit(ctx, nil, method, nil, key.key) != 1 {
		return PopError()
	}

	if len(data) > 0 {
		if C.X_EVP_DigestVerifyUpdate(ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
			return PopError()
		}
	}

	if C.X_EVP_DigestVerifyFinal(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig))) != 1 {
		return PopError()
	}

	return nil
}

func (key *pKey) MarshalPKCS8PrivateKeyPEM() ([]byte, error) {
	if key.key == nil {
		return nil, ErrEmptyKey
	}

	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if C.PEM_write_bio_PKCS8PrivateKey(bio, key.key, nil, nil, 0, nil, nil) != 1 {
		return nil, PopError()
	}

	var ptr *C.char
	length := C.X_BIO_get_mem_data(bio, &ptr)
	if length <= 0 {
		return nil, ErrNoData
	}

	result := C.GoBytes(unsafe.Pointer(ptr), C.int(length))
	return result, nil
}

// 这是公钥加解密，使用的接口与 SM4 那套 init update final 不同
func (key *pKey) Encrypt(data []byte) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(key.key, nil)
	defer C.EVP_PKEY_CTX_free(ctx)

	if C.EVP_PKEY_encrypt_init(ctx) != 1 {
		return nil, PopError()
	}

	var enclen C.size_t
	if C.EVP_PKEY_encrypt(ctx, nil, &enclen, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	enc := make([]byte, enclen)

	if C.EVP_PKEY_encrypt(ctx, (*C.uchar)(unsafe.Pointer(&enc[0])), &enclen, (*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	return enc[:enclen], nil
}

func (key *pKey) Decrypt(data []byte) ([]byte, error) {
	ctx := C.EVP_PKEY_CTX_new(key.key, nil)
	if ctx == nil {
		return nil, ErrMallocFailure
	}
	defer C.EVP_PKEY_CTX_free(ctx)

	if C.EVP_PKEY_decrypt_init(ctx) != 1 {
		return nil, PopError()
	}

	var declen C.size_t
	if C.EVP_PKEY_decrypt(ctx, nil, &declen, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	dec := make([]byte, declen)

	if C.EVP_PKEY_decrypt(ctx, (*C.uchar)(unsafe.Pointer(&dec[0])), &declen, (*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	return dec[:declen], nil
}

// Privatekey Publickey 序列化成密钥文件的函数 支持 PEM DER 格式

func (key *pKey) MarshalPKCS1PrivateKeyPEM() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	// PEM_write_bio_PrivateKey_traditional will use the key-specific PKCS1
	// format if one is available for that key type, otherwise it will encode
	// to a PKCS8 key.
	if int(C.X_PEM_write_bio_PrivateKey_traditional(bio, key.key, nil, nil,
		C.int(0), nil, nil)) != 1 {
		return nil, PopError()
	}

	pem, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return pem, nil
}

func (key *pKey) MarshalPKCS1PrivateKeyDER() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if int(C.i2d_PrivateKey_bio(bio, key.key)) != 1 {
		return nil, PopError()
	}

	ret, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return ret, nil
}

func (key *pKey) MarshalPKIXPublicKeyPEM() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if int(C.PEM_write_bio_PUBKEY(bio, key.key)) != 1 {
		return nil, PopError()
	}

	ret, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return ret, nil
}

func (key *pKey) MarshalPKIXPublicKeyDER() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if int(C.i2d_PUBKEY_bio(bio, key.key)) != 1 {
		return nil, PopError()
	}

	ret, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return ret, nil
}

//	将 PEM DER 格式的密钥文件读取进来并反序列化成 Privatekey Publickey
//
// LoadPrivateKeyFromPEM loads a private key from a PEM-encoded block.
func LoadPrivateKeyFromPEM(pemBlock []byte) (EVPPrivateKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrNoCert
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]),
		C.int(len(pemBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
	if key == nil {
		return nil, PopError()
	}

	priKey := &pKey{key: key}
	runtime.SetFinalizer(priKey, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	if C.X_EVP_PKEY_is_sm2(priKey.key) == 1 {
		if C.EVP_PKEY_set_alias_type(priKey.key, C.EVP_PKEY_SM2) != 1 {
			return nil, PopError()
		}
	}

	return priKey, nil
}

// LoadPrivateKeyFromPEMWithPassword loads a private key from a PEM-encoded block.
func LoadPrivateKeyFromPEMWithPassword(pemBlock []byte, password string) (
	EVPPrivateKey, error,
) {
	if len(pemBlock) == 0 {
		return nil, ErrNoKey
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]),
		C.int(len(pemBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)
	cs := C.CString(password)
	defer C.free(unsafe.Pointer(cs))
	key := C.PEM_read_bio_PrivateKey(bio, nil, nil, unsafe.Pointer(cs))
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}

// LoadPrivateKeyFromDER loads a private key from a DER-encoded block.
func LoadPrivateKeyFromDER(derBlock []byte) (EVPPrivateKey, error) {
	if len(derBlock) == 0 {
		return nil, ErrNoKey
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&derBlock[0]),
		C.int(len(derBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.d2i_PrivateKey_bio(bio, nil)
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}

// LoadPrivateKeyFromPEMWidthPassword loads a private key from a PEM-encoded block.
// Backwards-compatible with typo
func LoadPrivateKeyFromPEMWidthPassword(pemBlock []byte, password string) (
	EVPPrivateKey, error,
) {
	return LoadPrivateKeyFromPEMWithPassword(pemBlock, password)
}

// LoadPublicKeyFromPEM loads a public key from a PEM-encoded block.
func LoadPublicKeyFromPEM(pemBlock []byte) (EVPPublicKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrNoPubKey
	}

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]), C.int(len(pemBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.PEM_read_bio_PUBKEY(bio, nil, nil, nil)
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	return p, nil
}

// LoadPublicKeyFromDER loads a public key from a DER-encoded block.
func LoadPublicKeyFromDER(derBlock []byte) (EVPPublicKey, error) {
	if len(derBlock) == 0 {
		return nil, ErrNoPubKey
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&derBlock[0]),
		C.int(len(derBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.d2i_PUBKEY_bio(bio, nil)
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}

// GenerateRSAKey generates a new RSA private key with an exponent of 65537.
// func GenerateRSAKey(bits int) (EVPPrivateKey, error) {
// 	defaultPubExp := 0x10001

// 	return GenerateRSAKeyWithExponent(bits, defaultPubExp)
// }

// GenerateRSAKeyWithExponent generates a new RSA private key.
// func GenerateRSAKeyWithExponent(bits int, exponent int) (EVPPrivateKey, error) {
// 	rsa := C.RSA_generate_key(C.int(bits), C.ulong(exponent), nil, nil)
// 	if rsa == nil {
// 		return nil, ErrMallocFailure
// 	}
// 	key := C.X_EVP_PKEY_new()
// 	if key == nil {
// 		return nil, ErrMallocFailure
// 	}
// 	if C.X_EVP_PKEY_assign_charp(key, C.EVP_PKEY_RSA, (*C.char)(unsafe.Pointer(rsa))) != 1 {
// 		C.X_EVP_PKEY_free(key)
// 		return nil, PopError()
// 	}
// 	p := &pKey{key: key}
// 	runtime.SetFinalizer(p, func(p *pKey) {
// 		C.X_EVP_PKEY_free(p.key)
// 	})
// 	return p, nil
// }

// EllipticCurve repesents the ASN.1 OID of an elliptic curve.
// see https://www.openssl.org/docs/apps/ecparam.html for a list of implemented curves.
type EllipticCurve int

const (
	// P-256: X9.62/SECG curve over a 256 bit prime field
	Prime256v1 EllipticCurve = C.NID_X9_62_prime256v1
	// P-384: NIST/SECG curve over a 384 bit prime field
	Secp384r1 EllipticCurve = C.NID_secp384r1
	// P-521: NIST/SECG curve over a 521 bit prime field
	Secp521r1 EllipticCurve = C.NID_secp521r1
	// SM2:	GB/T 32918-2017
	SM2Curve EllipticCurve = C.NID_sm2
)

// GenerateECKey generates a new elliptic curve private key on the speicified
// curve.
func GenerateECKey(curve EllipticCurve) (EVPPrivateKey, error) {
	// Create context for parameter generation
	paramCtx := C.EVP_PKEY_CTX_new_id(C.EVP_PKEY_EC, nil)
	if paramCtx == nil {
		return nil, PopError()
	}
	defer C.EVP_PKEY_CTX_free(paramCtx)

	if curve == SM2Curve {
		if C.EVP_PKEY_keygen_init(paramCtx) != 1 {
			return nil, PopError()
		}
	} else {
		if int(C.EVP_PKEY_paramgen_init(paramCtx)) != 1 {
			return nil, PopError()
		}
	}

	// Set curve in EC parameter generation context
	if int(C.X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx, C.int(curve))) != 1 {
		return nil, PopError()
	}

	var key *C.EVP_PKEY

	if curve == SM2Curve {
		if int(C.EVP_PKEY_keygen(paramCtx, &key)) != 1 {
			return nil, PopError()
		}
	} else {
		// Create parameter object
		var params *C.EVP_PKEY
		if int(C.EVP_PKEY_paramgen(paramCtx, &params)) != 1 {
			return nil, PopError()
		}
		defer C.EVP_PKEY_free(params)

		// Create context for the key generation
		keyCtx := C.EVP_PKEY_CTX_new(params, nil)
		if keyCtx == nil {
			return nil, PopError()
		}
		defer C.EVP_PKEY_CTX_free(keyCtx)

		if int(C.EVP_PKEY_keygen_init(keyCtx)) != 1 {
			return nil, PopError()
		}

		if int(C.EVP_PKEY_keygen(keyCtx, &key)) != 1 {
			return nil, PopError()
		}
	}

	privKey := &pKey{key: key}
	runtime.SetFinalizer(privKey, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	if curve == SM2Curve {
		if C.EVP_PKEY_set_alias_type(privKey.key, C.EVP_PKEY_SM2) != 1 {
			return nil, PopError()
		}
	}

	return privKey, nil
}

// GenerateED25519Key generates a Ed25519 key
func GenerateED25519Key() (EVPPrivateKey, error) {
	// Key context
	keyCtx := C.EVP_PKEY_CTX_new_id(C.X_EVP_PKEY_ED25519, nil)
	if keyCtx == nil {
		return nil, PopError()
	}
	defer C.EVP_PKEY_CTX_free(keyCtx)

	// Generate the key
	var privKey *C.EVP_PKEY
	if int(C.EVP_PKEY_keygen_init(keyCtx)) != 1 {
		return nil, PopError()
	}
	if int(C.EVP_PKEY_keygen(keyCtx, &privKey)) != 1 {
		return nil, PopError()
	}

	p := &pKey{key: privKey}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}

// ToECKey converts the EVPPrivateKey or EVPPublicKey to an *ECKey.
// This is used for interoperability with APIs that require *ECKey (e.g. sm2keyexch).
func ToECKey(k interface{}) (*ECKey, error) {
	if pk, ok := k.(*pKey); ok {
		return pk.ToECKey()
	}
	return nil, fmt.Errorf("unsupported key type, possibly not an OpenSSL backed key")
}

func (key *pKey) ToECKey() (*ECKey, error) {
	if key.key == nil {
		return nil, ErrEmptyKey
	}
	// Check identity
	if key.BaseType() != KeyTypeEC && key.KeyType() != KeyTypeSM2 {
		return nil, fmt.Errorf("key is not an EC or SM2 key (type: %d)", key.KeyType())
	}

	ecKeyPtr := C.X_EVP_PKEY_get1_EC_KEY(key.key)
	if ecKeyPtr == nil {
		return nil, fmt.Errorf("EVP_PKEY_get1_EC_KEY failed")
	}

	return &ECKey{ptr: ecKeyPtr}, nil
}

// bio.go 部分

// type anyBio C.BIO

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

// //export go_write_bio_write
// func go_write_bio_write(bio *C.BIO, data *C.char, size C.int) C.int {
// 	var rc C.int

// 	defer func() {
// 		if err := recover(); err != nil {
// 			// logger.Critf("openssl: writeBioWrite panic'd: %v", err)
// 			rc = -1
// 		}
// 	}()
// 	// 从 C BIO 中获取 GO WriteBio 指针
// 	ptr := loadWritePtr(bio)
// 	if ptr == nil || data == nil || size < 0 {
// 		return -1
// 	}

// 	// 上 GO WriteBio 数据锁
// 	ptr.dataMtx.Lock()
// 	defer ptr.dataMtx.Unlock()

// 	// 重置 C BIO 状态，清除重试标志
// 	bioClearRetryFlags(bio)
// 	// 把 C BIO 的数据转化为 Go 字节切片追加到 GO WriteBio 的缓冲区
// 	ptr.buf = append(ptr.buf, nonCopyCString(data, size)...)
// 	rc = size

// 	return rc
// }

// //export go_write_bio_ctrl
// func go_write_bio_ctrl(bio *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) C.long {
// 	_, _ = arg1, arg2 // unused

// 	var rc C.long

// 	// 使用 defer 和 recover 捕获潜在的 panic，防止Go panic传播到 C 代码
// 	// 发生 panic 时返回 -1
// 	defer func() {
// 		if err := recover(); err != nil {
// 			// logger.Critf("openssl: writeBioCtrl panic'd: %v", err)
// 			rc = -1
// 		}
// 	}()

// 	switch cmd {

// 	// 查询 BIO 中待处理（待写入）的数据量，调用 writeBioPending 函数获取
// 	case C.BIO_CTRL_WPENDING:
// 		rc = writeBioPending(bio)
// 	// 处理 BIO_CTRL_DUP 和 BIO_CTRL_FLUSH 命令，返回 1 表示成功
// 	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
// 		rc = 1
// 	default:
// 		rc = 0
// 	}

// 	return rc
// }

// //export go_read_bio_read
// func go_read_bio_read(bio *C.BIO, data *C.char, size C.int) C.int {
// 	rc := 0

// 	defer func() {
// 		if err := recover(); err != nil {
// 			// logger.Critf("openssl: go_read_bio_read panic'd: %v", err)
// 			rc = -1
// 		}
// 	}()

// 	ptr := loadReadPtr(bio)
// 	if ptr == nil || size < 0 {
// 		return -1
// 	}

// 	ptr.dataMtx.Lock()
// 	defer ptr.dataMtx.Unlock()

// 	// 清除重试标记
// 	bioClearRetryFlags(bio)

// 	if len(ptr.buf) == 0 {
// 		// 如果 buf 中没有数据，并且 eof 标志为 true
// 		// 则返回 0 表示已没有数据可读
// 		if ptr.eof {
// 			return 0
// 		}
// 		// 如果 buf 中没有数据，且 eof 标志为 false
// 		// 则设置重试读取标志并返回 -1
// 		// 表示需要等待数据来了再读
// 		bioSetRetryRead(bio)
// 		return -1
// 	}
// 	// 当请求读取 0 字节或目标缓冲区为 nil 时
// 	// 返回当前可用数据量而不进行实际读取
// 	if size == 0 || data == nil {
// 		return C.int(len(ptr.buf))
// 	}
// 	// 创建指向 C 缓冲区的 Go 切片视图
// 	// 将数据从 Go ReadBio 缓冲区复制到 C 缓冲区的 Go 切片视图中
// 	rc = copy(nonCopyCString(data, size), ptr.buf)
// 	// 从 Go ReadBio 缓冲区中删除已读取的数据
// 	// 把未读取的数据前移，并把后面多余的截掉
// 	ptr.buf = ptr.buf[:copy(ptr.buf, ptr.buf[rc:])]
// 	// 如果允许 release 并且 ReadBio 的 buf 被读空了
// 	// 就设置 buf 为 nil
// 	if ptr.releaseBuffers && len(ptr.buf) == 0 {
// 		ptr.buf = nil
// 	}
// 	return C.int(rc)
// }

// //export go_read_bio_ctrl
// func go_read_bio_ctrl(bio *C.BIO, cmd C.int, arg1 C.long, arg2 unsafe.Pointer) C.long {
// 	_, _ = arg1, arg2 // unused

// 	var rc C.long
// 	defer func() {
// 		if err := recover(); err != nil {
// 			// logger.Critf("openssl: readBioCtrl panic'd: %v", err)
// 			rc = -1
// 		}
// 	}()

// 	switch cmd {
// 	// 获取 Go ReadBio 剩余数据的长度
// 	case C.BIO_CTRL_PENDING:
// 		rc = readBioPending(bio)
// 	case C.BIO_CTRL_DUP, C.BIO_CTRL_FLUSH:
// 		rc = 1
// 	default:
// 		rc = 0
// 	}

// 	return rc
// }

// type WriteBio struct {
// 	dataMtx        sync.Mutex
// 	opMtx          sync.Mutex
// 	buf            []byte
// 	releaseBuffers bool
// }

// func loadWritePtr(b *C.BIO) *WriteBio {
// 	// 从 C BIO 中获取 token
// 	t := token(C.X_BIO_get_data(b))

// 	// 从 WriteBio 映射表获取对应的 GO WriteBio 地址
// 	return (*WriteBio)(writeBioMapping.Get(t))
// }

func LoadPrivateKeyFileFromPEM(path string) (EVPPrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadPrivateKeyFromPEM(data)
}

func LoadPrivateKeyFileFromPEMWithPassword(path, password string) (EVPPrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadPrivateKeyFromPEMWithPassword(data, password)
}

func LoadPrivateKeyFileFromDER(path string) (EVPPrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadPrivateKeyFromDER(data)
}

func LoadPublicKeyFileFromPEM(path string) (EVPPublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadPublicKeyFromPEM(data)
}

func LoadPublicKeyFileFromDER(path string) (EVPPublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadPublicKeyFromDER(data)
}
