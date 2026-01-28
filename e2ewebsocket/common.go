package e2ewebsocket

import (
	"crypto"
	"crypto/rand"
	"io"
	"slices"

	"github.com/albert/ws_client/compressor"
	"github.com/albert/ws_client/encoder"
)

const (
	maxPlaintext = 16384
	maxHandshake = 65536
)

// signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// 签名算法类型
const (
	signaturePKCS1v15 uint8 = iota + 225
	signatureRSAPSS
	signatureECDSA
	signatureEd25519
	// 新增国密
	signatureSM2
)

// 只签名不哈希
var directSigning crypto.Hash = 0

// 签名方案类型（签名+哈希）
type SignatureScheme uint16

const (
	// RSASSA-PKCS1-v1_5 algorithms.
	PKCS1WithSHA256 SignatureScheme = 0x0401
	PKCS1WithSHA384 SignatureScheme = 0x0501
	PKCS1WithSHA512 SignatureScheme = 0x0601

	// RSASSA-PSS algorithms with public key OID rsaEncryption.
	PSSWithSHA256 SignatureScheme = 0x0804
	PSSWithSHA384 SignatureScheme = 0x0805
	PSSWithSHA512 SignatureScheme = 0x0806

	// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	ECDSAWithP521AndSHA512 SignatureScheme = 0x0603

	// EdDSA algorithms.
	Ed25519 SignatureScheme = 0x0807

	// Legacy signature and hash algorithms for TLS 1.2.
	PKCS1WithSHA1 SignatureScheme = 0x0201
	ECDSAWithSHA1 SignatureScheme = 0x0203

	// 新增国密
	SM2WithSM3 SignatureScheme = 0x0909
)

// 握手消息类型
const (
	typeHelloRequest uint8 = 0
	typeHelloMsg     uint8 = 1

	typeKeyExchange        uint8 = 12
	typeCertificateRequest uint8 = 13
	typeFinished           uint8 = 20
	typeKeyUpdate          uint8 = 24
	typeMessageHash        uint8 = 254 // synthetic message
)

const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionExtendedMasterSecret    uint16 = 23
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionQUICTransportParameters uint16 = 57
	extensionRenegotiationInfo       uint16 = 0xff01
	extensionECHOuterExtensions      uint16 = 0xfd00
	extensionEncryptedClientHello    uint16 = 0xfe0d
)

type recordType uint8

const (
	// 只保留两种 握手数据类型和应用数据类型
	// 至于 Close 类型的在更外层也就是 ws 的 msgType 那一级处理了
	// msgType 中的二进制数据再细分为 握手和应用两种
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
	recordTypeChangeCipherSpec recordType = 24
)

type RenegotiationSupport int

const (
	// RenegotiateNever disables renegotiation.
	RenegotiateNever RenegotiationSupport = iota

	// RenegotiateOnceAsClient allows a remote server to request
	// renegotiation once per connection.
	RenegotiateOnceAsClient

	// RenegotiateFreelyAsClient allows a remote server to repeatedly
	// request renegotiation.
	RenegotiateFreelyAsClient
)

type CurveID uint16

const (
	CurveP256      CurveID = 23
	CurveP384      CurveID = 24
	CurveP521      CurveID = 25
	X25519         CurveID = 29
	X25519MLKEM768 CurveID = 4588
	SM2CurveP256V1 CurveID = 4152
	// SM2MLKEM768 CurveID = 4589
)

const (
	VersionE2E1 = 0x0301
	VersionE2E2 = 0x0302
)

var supportedVersions = []uint16{
	VersionE2E1,
	VersionE2E2,
}

type Config struct {
	Version uint16

	Rand io.Reader

	supportedVersions []uint16

	// Renegotiation controls what types of renegotiation are supported.
	// The default, none, is correct for the vast majority of applications.
	Renegotiation RenegotiationSupport

	CipherSuites []uint16

	CurvePreferences          []CurveID
	SignatureSchemePreference []SignatureScheme

	KeyStorePath string

	Compressor compressor.Compressor
	Encoder    encoder.Encoder
}

// 默认密钥存储路径：可以给一个系统路径，目前先用工作区路径
var defaultKeyStorePath string = "./e2ewebsocket/static_key"

// 压缩器
// compressor := compressor.NewGzipCompressor()
// 编码器【要用Gob】
// encoder := encoder.NewGobEncoder()

var emptyConfig Config

func defaultConfig() *Config {
	cfg := emptyConfig
	return &cfg
}

func (c *Config) keyStorePath() string {
	if c.KeyStorePath == "" {
		return defaultKeyStorePath
	}
	return c.KeyStorePath
}

func (c *Config) compressor() compressor.Compressor {
	if c.Compressor == nil {
		return compressor.NewGzipCompressor()
	}
	return c.Compressor
}

func (c *Config) encoder() encoder.Encoder {
	if c.Encoder == nil {
		return encoder.NewGobEncoder()
	}
	return c.Encoder
}

func (c *Config) cipherSuites() []uint16 {
	if c.CipherSuites == nil {
		return defaultCipherSuites()
	}
	return c.CipherSuites
}

func defaultCipherSuites() []uint16 {
	return cipherSuitesPreferenceOrder
}

func (c *Config) supportedSignatureAlgorithms() []SignatureScheme {
	return defaultSupportedSignatureAlgorithms
}

func (c *Config) curvePreferences(version uint16) []CurveID {
	var curvePreferences []CurveID

	curvePreferences = defaultCurvePreferences()

	if c != nil && len(c.CurvePreferences) != 0 {
		curvePreferences = slices.DeleteFunc(curvePreferences, func(x CurveID) bool {
			return !slices.Contains(c.CurvePreferences, x)
		})
	}
	return curvePreferences
}

// var isMlkem = godebug.New("mlkem")

func defaultCurvePreferences() []CurveID {
	// if isMlkem.Value() == "0" {
	// 	return []CurveID{X25519, CurveP256, CurveP384, CurveP521}
	// }
	return []CurveID{X25519MLKEM768, X25519, CurveP256, CurveP384, CurveP521}
}

func (c *Config) rand() io.Reader {
	r := c.Rand
	if r == nil {
		return rand.Reader
	}
	return r
}

func (c *Config) mutualVersion(peerVersions []uint16) (uint16, bool) {
	if len(peerVersions) == 0 {
		return 0, false
	}
	supported := c.supportedVersions
	if supported == nil {
		supported = c.defaultSupportedVersions()
	}
	peerSet := make(map[uint16]struct{}, len(peerVersions))
	for _, v := range peerVersions {
		peerSet[v] = struct{}{}
	}
	var picked uint16
	found := false
	for _, v := range supported {
		if _, ok := peerSet[v]; ok {
			if !found || v > picked {
				picked = v
				found = true
			}
		}
	}
	if !found {
		return 0, false
	}
	return picked, true
}

func (c *Config) defaultSupportedVersions() []uint16 {
	return supportedVersions
}

type handshakeMessage interface {
	marshal() ([]byte, error)
	unmarshal([]byte) bool
}

type handshakeMessageWithOriginalBytes interface {
	handshakeMessage
	originalBytes() []byte
}
