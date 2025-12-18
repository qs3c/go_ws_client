package e2ewebsocket

import (
	"context"
	"crypto/mlkem"
	"crypto/tls/internal/fips140tls"
	"errors"
	"io"
	"slices"
)

// type clientHandshakeState struct {
// 	c            *Conn
// 	ctx          context.Context
// 	serverHello  *serverHelloMsg
// 	hello        *clientHelloMsg
// 	suite        *cipherSuite
// 	finishedHash finishedHash
// 	masterSecret []byte
// 	session      *SessionState // the session being resumed
// 	ticket       []byte        // a fresh ticket received during this handshake
// }

// type serverHandshakeState struct {
// 	c            *Conn
// 	ctx          context.Context
// 	clientHello  *clientHelloMsg
// 	hello        *serverHelloMsg
// 	suite        *cipherSuite
// 	ecdheOk      bool
// 	ecSignOk     bool
// 	rsaDecryptOk bool
// 	rsaSignOk    bool
// 	sessionState *SessionState
// 	finishedHash finishedHash
// 	masterSecret []byte
// 	cert         *Certificate
// }

type handshakeState struct {
	c            *Conn
	ctx          context.Context
	helloMsg     *serverHelloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
}

func (c *Conn) symHandshake(ctx context.Context) (err error) {

	if c.config == nil {
		c.config = defaultConfig()
	}

	// 【第一大步：生成客户端 Hello】
	hello, keyShareKeys, ech, err := c.makeHello()
	if err != nil {
		return err
	}

	// 【第二大步：发送 ClientHello 消息】
	if _, err := c.writeHandshakeRecord(hello, nil); err != nil {
		return err
	}

	// serverHelloMsg is not included in the transcript
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	serverHello, ok := msg.(*serverHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(serverHello, msg)
	}

	if err := c.pickE2EVersion(serverHello); err != nil {
		return err
	}

	hs := &handshakeState{
		c:           c,
		ctx:         ctx,
		serverHello: serverHello,
		hello:       hello,
		session:     session,
	}
	return hs.handshake()
}

func (c *Conn) makeHello() (*clientHelloMsg, *keySharePrivateKeys, error) {

	config := c.config

	version := config.Version

	supportedVersions := config.supportedVersions
	if len(supportedVersions) == 0 {
		return nil, nil, nil, errors.New("tls: no supported versions satisfy MinVersion and MaxVersion")
	}

	hello := &helloMsg{
		vers:                         version,
		random:                       make([]byte, 32),
		supportedCurves:              config.curvePreferences(maxVersion),
		supportedPoints:              []uint8{pointFormatUncompressed},
		secureRenegotiationSupported: true,
		supportedVersions:            supportedVersions,
	}

	if c.handshakes > 0 {
		hello.secureRenegotiation = c.clientFinished[:]
	}

	// 基于硬件条件设置prefer order xx
	// cipherSuitesPreferenceOrder 是 cipher suite 的 id 列表
	preferenceOrder := cipherSuitesPreferenceOrder
	// if !hasAESGCMHardwareSupport {
	// 	preferenceOrder = cipherSuitesPreferenceOrderNoAES
	// }
	configCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(configCipherSuites))

	for _, suiteId := range preferenceOrder {
		suite := mutualCipherSuite(configCipherSuites, suiteId)
		if suite == nil {
			continue
		}
		// Don't advertise TLS 1.2-only cipher suites unless
		// we're attempting TLS 1.2.
		if maxVersion < VersionTLS12 && suite.flags&suiteTLS12 != 0 {
			continue
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}

	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, nil, nil, errors.New("tls: short read from Rand: " + err.Error())
	}

	// A random session ID is used to detect when the server accepted a ticket
	// and is resuming a session (see RFC 5077). In TLS 1.3, it's always set as
	// a compatibility measure (see RFC 8446, Section 4.1.2).
	//
	// The session ID is not set for QUIC connections (see RFC 9001, Section 8.4).
	if c.quic == nil {
		hello.sessionId = make([]byte, 32)
		if _, err := io.ReadFull(config.rand(), hello.sessionId); err != nil {
			return nil, nil, nil, errors.New("tls: short read from Rand: " + err.Error())
		}
	}

	if maxVersion >= VersionTLS12 {
		hello.supportedSignatureAlgorithms = supportedSignatureAlgorithms()
	}
	if testingOnlyForceClientHelloSignatureAlgorithms != nil {
		hello.supportedSignatureAlgorithms = testingOnlyForceClientHelloSignatureAlgorithms
	}

	var keyShareKeys *keySharePrivateKeys
	if hello.supportedVersions[0] == VersionTLS13 {
		// Reset the list of ciphers when the client only supports TLS 1.3.
		if len(hello.supportedVersions) == 1 {
			hello.cipherSuites = nil
		}
		if fips140tls.Required() {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13FIPS...)
		} else if hasAESGCMHardwareSupport {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13...)
		} else {
			hello.cipherSuites = append(hello.cipherSuites, defaultCipherSuitesTLS13NoAES...)
		}

		if len(hello.supportedCurves) == 0 {
			return nil, nil, nil, errors.New("tls: no supported elliptic curves for ECDHE")
		}
		curveID := hello.supportedCurves[0]
		keyShareKeys = &keySharePrivateKeys{curveID: curveID}
		// Note that if X25519MLKEM768 is supported, it will be first because
		// the preference order is fixed.
		if curveID == X25519MLKEM768 {
			keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), X25519)
			if err != nil {
				return nil, nil, nil, err
			}
			seed := make([]byte, mlkem.SeedSize)
			if _, err := io.ReadFull(config.rand(), seed); err != nil {
				return nil, nil, nil, err
			}
			keyShareKeys.mlkem, err = mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				return nil, nil, nil, err
			}
			mlkemEncapsulationKey := keyShareKeys.mlkem.EncapsulationKey().Bytes()
			x25519EphemeralKey := keyShareKeys.ecdhe.PublicKey().Bytes()
			hello.keyShares = []keyShare{
				{group: X25519MLKEM768, data: append(mlkemEncapsulationKey, x25519EphemeralKey...)},
			}
			// If both X25519MLKEM768 and X25519 are supported, we send both key
			// shares (as a fallback) and we reuse the same X25519 ephemeral
			// key, as allowed by draft-ietf-tls-hybrid-design-09, Section 3.2.
			if slices.Contains(hello.supportedCurves, X25519) {
				hello.keyShares = append(hello.keyShares, keyShare{group: X25519, data: x25519EphemeralKey})
			}
		} else {
			if _, ok := curveForCurveID(curveID); !ok {
				return nil, nil, nil, errors.New("tls: CurvePreferences includes unsupported curve")
			}
			keyShareKeys.ecdhe, err = generateECDHEKey(config.rand(), curveID)
			if err != nil {
				return nil, nil, nil, err
			}
			hello.keyShares = []keyShare{{group: curveID, data: keyShareKeys.ecdhe.PublicKey().Bytes()}}
		}
	}

	return hello, keyShareKeys, nil
}
