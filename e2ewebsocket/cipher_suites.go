package e2ewebsocket

import (
	"crypto/cipher"
	"hash"

	"github.com/albert/ws_client/crypto/sm4tongsuo"
)

// ciphersuite 的 flags 字段与对象
// 这种特性集合字段的与对象，用 1 << iota 特别合适！
// 刚好是:
// 0001
// 0010
// 0100
// 1000
const (
	// suiteECDHE indicates that the cipher suite involves elliptic curve
	// Diffie-Hellman. This means that it should only be selected when the
	// client indicates that it supports ECC with a curve and point format
	// that we're happy with.
	suiteECDHE = 1 << iota
	// suiteECSign indicates that the cipher suite involves an ECDSA or
	// EdDSA signature and therefore may only be selected when the server's
	// certificate is ECDSA or EdDSA. If this is not set then the cipher suite
	// is RSA based.
	suiteECSign
	// suiteTLS12 indicates that the cipher suite should only be advertised
	// and accepted when using TLS 1.2.
	suiteTLS12
	// suiteSHA384 indicates that the cipher suite uses SHA384 as the
	// handshake hash.
	suiteSHA384

	suiteSM3
)

const (
	// 国密SM2密钥交换+SM4-SM3
	E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3 uint16 = 0x002b
	E2E_SM2KEYAGREEMENT_WITH_SM4_256_GCM_SM3 uint16 = 0x002c
	E2E_SM2KEYAGREEMENT_WITH_SM4_512_GCM_SM3 uint16 = 0x002d
	E2E_SM2KEYAGREEMENT_WITH_SM4_128_CBC_SM3 uint16 = 0x002e
	E2E_SM2KEYAGREEMENT_WITH_SM4_256_CBC_SM3 uint16 = 0x002f
	E2E_SM2KEYAGREEMENT_WITH_SM4_512_CBC_SM3 uint16 = 0x0030

	// 后量子MLKEM+SM4-GCM-SM3
	E2E_MLKEMSM2_WITH_SM4_128_GCM_SM3 uint16 = 0x0031
	E2E_MLKEMSM2_WITH_SM4_256_GCM_SM3 uint16 = 0x0032
	E2E_MLKEMSM2_WITH_SM4_512_GCM_SM3 uint16 = 0x0033

	// TLS 1.0 - 1.2 cipher suites.
	TLS_RSA_WITH_RC4_128_SHA                      uint16 = 0x0005
	TLS_RSA_WITH_3DES_EDE_CBC_SHA                 uint16 = 0x000a
	TLS_RSA_WITH_AES_128_CBC_SHA                  uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA                  uint16 = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256               uint16 = 0x003c
	TLS_RSA_WITH_AES_128_GCM_SHA256               uint16 = 0x009c
	TLS_RSA_WITH_AES_256_GCM_SHA384               uint16 = 0x009d
	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA              uint16 = 0xc007
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA          uint16 = 0xc009
	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA          uint16 = 0xc00a
	TLS_ECDHE_RSA_WITH_RC4_128_SHA                uint16 = 0xc011
	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA           uint16 = 0xc012
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA            uint16 = 0xc013
	TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA            uint16 = 0xc014
	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256       uint16 = 0xc023
	TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256         uint16 = 0xc027
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256         uint16 = 0xc02f
	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256       uint16 = 0xc02b
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384         uint16 = 0xc030
	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384       uint16 = 0xc02c
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256   uint16 = 0xcca8
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 uint16 = 0xcca9

	// TLS 1.3 cipher suites.
	TLS_AES_128_GCM_SHA256       uint16 = 0x1301
	TLS_AES_256_GCM_SHA384       uint16 = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 uint16 = 0x1303

	// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
	// that the client is doing version fallback. See RFC 7507.
	TLS_FALLBACK_SCSV uint16 = 0x5600

	// Legacy names for the corresponding cipher suites with the correct _SHA256
	// suffix, retained for backward compatibility.
	TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305   = TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305 = TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
)

var cipherSuitesPreferenceOrder = []uint16{
	// 国密
	E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3,
	E2E_SM2KEYAGREEMENT_WITH_SM4_256_GCM_SM3,
	E2E_SM2KEYAGREEMENT_WITH_SM4_512_GCM_SM3,
	E2E_SM2KEYAGREEMENT_WITH_SM4_128_CBC_SM3,
	E2E_SM2KEYAGREEMENT_WITH_SM4_256_CBC_SM3,
	E2E_SM2KEYAGREEMENT_WITH_SM4_512_CBC_SM3,

	// 混合后量子
	E2E_MLKEMSM2_WITH_SM4_128_GCM_SM3,
	E2E_MLKEMSM2_WITH_SM4_256_GCM_SM3,
	E2E_MLKEMSM2_WITH_SM4_512_GCM_SM3,
}

// 目前密码套件仅一种实现
var cipherSuites = map[uint16]*cipherSuite{
	E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3: {E2E_SM2KEYAGREEMENT_WITH_SM4_128_GCM_SM3, 16, 0, 4, sm2KA, suiteTLS12, nil, nil, sm4tongsuo.NewSm4AEADCipher},
	// E2E_MLKEMSM2_WITH_SM4_128_GCM_SM3: {E2E_MLKEMSM2_WITH_SM4_128_GCM_SM3, 16, 0, 4, mlkemsm2KA, suiteTLS12, nil, nil, sm4tongsuo.NewSm4AEADCipher},
}

type cipherSuite struct {
	id uint16
	// the lengths, in bytes, of the key material needed for each component.
	keyLen int
	macLen int
	ivLen  int
	// ka     func(version uint16) keyAgreement
	ka keyAgreement
	// flags is a bitmask of the suite* values, above.
	flags  int
	cipher func(key, iv []byte, isRead bool) any
	mac    func(key []byte) hash.Hash
	aead   func(key, fixedNonce []byte) cipher.AEAD
}

// var cipherSuites = []*cipherSuite{ // TODO: replace with a map, since the order doesn't matter.
// 	{TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
// 	{TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, 32, 0, 12, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, nil, nil, aeadChaCha20Poly1305},
// 	{TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12, nil, nil, aeadAESGCM},
// 	{TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, nil, nil, aeadAESGCM},
// 	{TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheRSAKA, suiteECDHE | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
// 	{TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
// 	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdheRSAKA, suiteECDHE | suiteTLS12, cipherAES, macSHA256, nil},
// 	{TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
// 	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, ecdheECDSAKA, suiteECDHE | suiteECSign | suiteTLS12, cipherAES, macSHA256, nil},
// 	{TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, 16, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECSign, cipherAES, macSHA1, nil},
// 	{TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheRSAKA, suiteECDHE, cipherAES, macSHA1, nil},
// 	{TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, 32, 20, 16, ecdheECDSAKA, suiteECDHE | suiteECSign, cipherAES, macSHA1, nil},
// 	{TLS_RSA_WITH_AES_128_GCM_SHA256, 16, 0, 4, rsaKA, suiteTLS12, nil, nil, aeadAESGCM},
// 	{TLS_RSA_WITH_AES_256_GCM_SHA384, 32, 0, 4, rsaKA, suiteTLS12 | suiteSHA384, nil, nil, aeadAESGCM},
// 	{TLS_RSA_WITH_AES_128_CBC_SHA256, 16, 32, 16, rsaKA, suiteTLS12, cipherAES, macSHA256, nil},
// 	{TLS_RSA_WITH_AES_128_CBC_SHA, 16, 20, 16, rsaKA, 0, cipherAES, macSHA1, nil},
// 	{TLS_RSA_WITH_AES_256_CBC_SHA, 32, 20, 16, rsaKA, 0, cipherAES, macSHA1, nil},
// 	{TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, ecdheRSAKA, suiteECDHE, cipher3DES, macSHA1, nil},
// 	{TLS_RSA_WITH_3DES_EDE_CBC_SHA, 24, 20, 8, rsaKA, 0, cipher3DES, macSHA1, nil},
// 	{TLS_RSA_WITH_RC4_128_SHA, 16, 20, 0, rsaKA, 0, cipherRC4, macSHA1, nil},
// 	{TLS_ECDHE_RSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheRSAKA, suiteECDHE, cipherRC4, macSHA1, nil},
// 	{TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, 16, 20, 0, ecdheECDSAKA, suiteECDHE | suiteECSign, cipherRC4, macSHA1, nil},
// }

// var cipherSuitesPreferenceOrderNoAES = []uint16{
// 	// ChaCha20Poly1305
// 	TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305, TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,

// 	// AES-GCM w/ ECDHE
// 	TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
// 	TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,

// 	// The rest of cipherSuitesPreferenceOrder.
// 	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
// 	TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
// 	TLS_RSA_WITH_AES_128_GCM_SHA256,
// 	TLS_RSA_WITH_AES_256_GCM_SHA384,
// 	TLS_RSA_WITH_AES_128_CBC_SHA,
// 	TLS_RSA_WITH_AES_256_CBC_SHA,
// 	TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
// 	TLS_RSA_WITH_3DES_EDE_CBC_SHA,
// 	TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
// 	TLS_RSA_WITH_AES_128_CBC_SHA256,
// 	TLS_ECDHE_ECDSA_WITH_RC4_128_SHA, TLS_ECDHE_RSA_WITH_RC4_128_SHA,
// 	TLS_RSA_WITH_RC4_128_SHA,
// }

func mutualCipherSuiteOld(have []uint16, want uint16) *cipherSuite {
	for _, id := range have {
		if id == want {
			return cipherSuiteByID(id)
		}
	}
	return nil
}

func mutualCipherSuite(have []uint16, want []uint16) *cipherSuite {
	pickedCiphersuite := Intersection(have, want)
	if pickedCiphersuite == 0 {
		return nil
	}
	return cipherSuiteByID(pickedCiphersuite)
}

// 暂时放在这，放这里不太合适其实
func mutualSignatureScheme(have []SignatureScheme, want []SignatureScheme) SignatureScheme {
	pickedSignatureScheme := Intersection(have, want)
	if pickedSignatureScheme == 0 {
		return 0
	}
	return pickedSignatureScheme
}

func cipherSuiteByID(id uint16) *cipherSuite {
	suite, ok := cipherSuites[id]
	if !ok {
		return nil
	}
	return suite
}

var sm2KA = &sm2KeyAgreement{}

// func sm2KA(version uint16) keyAgreement {
// 	return &sm2KeyAgreement{}
// }

// ok已经知道了，ciphersuite中的ka就是一个keyAgreement实例，并不是ka的id什么的
// 不像 cipher+mac 或者 aead，他们是在 cipher 中不是实例，而是根据入参（密钥,随机值之类的）返回对应实例的函数
// 所以我在协商pickciphersuite套件的时候，就要把ka初始化好
// 冲突，但是pickciphersuite的时候，其实是从已经提前预备好的 ciphersuites 列表里面去找
// 而 sm2 的特点是无法提前预备好！因为不知道id信息，预备半好试试
