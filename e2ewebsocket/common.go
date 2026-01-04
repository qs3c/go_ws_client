package e2ewebsocket

import (
	"crypto/rand"
	"internal/godebug"
	"io"
	"slices"
)

const (
	maxPlaintext = 16384
	maxHandshake = 65536
)

// signaling cipher suite values
const (
	scsvRenegotiation uint16 = 0x00ff
)

// 握手消息类型
const (
	typeHelloRequest uint8 = 0
	typeHelloMsg     uint8 = 1

	typeKeyExchange        uint8 = 12
	typeCertificateRequest uint8 = 13
	typeHelloDone          uint8 = 14
	typeCertificateVerify  uint8 = 15
	typeClientKeyExchange  uint8 = 16
	typeFinished           uint8 = 20
	typeCertificateStatus  uint8 = 22
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
	recordTypeHandshake       recordType = 22
	recordTypeApplicationData recordType = 23
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

	CurvePreferences []CurveID
}

var emptyConfig Config

func defaultConfig() *Config {
	return &emptyConfig
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

var isMlkem = godebug.New("mlkem")

func defaultCurvePreferences() []CurveID {
	if isMlkem.Value() == "0" {
		return []CurveID{X25519, CurveP256, CurveP384, CurveP521}
	}
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
	pickedVersion := Intersection(c.supportedVersions, peerVersions)
	if peerVersions == nil {
		return 0, false
	}
	return pickedVersion, true
}

func (c *Config) defaultSupportedVersions() []uint16 {
	return supportedVersions
}

type handshakeMessage interface {
	marshal() ([]byte, error)
	unmarshal([]byte) bool
}
