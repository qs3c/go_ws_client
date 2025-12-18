package e2ewebsocket

type recordType uint8

const (
	recordTypeChangeCipherSpec recordType = 20
	recordTypeAlert            recordType = 21
	recordTypeHandshake        recordType = 22
	recordTypeApplicationData  recordType = 23
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

type Config struct {
	Version uint16

	supportedVersions []uint16

	// Renegotiation controls what types of renegotiation are supported.
	// The default, none, is correct for the vast majority of applications.
	Renegotiation RenegotiationSupport

	CipherSuites []uint16
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
