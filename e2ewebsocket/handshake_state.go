package e2ewebsocket

import (
	"context"
	"errors"
	"io"
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
	helloMsg     *helloMsg
	suite        *cipherSuite
	finishedHash finishedHash
	masterSecret []byte
}

func (c *Conn) symHandshake(ctx context.Context) (err error) {

	if c.config == nil {
		c.config = defaultConfig()
	}

	// 【第一大步：生成客户端 Hello】
	hello, err := c.makeHello()
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

func (c *Conn) makeHello() (*helloMsg, error) {

	config := c.config

	version := config.Version

	supportedVersions := config.supportedVersions
	if len(supportedVersions) == 0 {
		return nil, errors.New("tls: no supported versions satisfy MinVersion and MaxVersion")
	}

	hello := &helloMsg{
		supportedVersions:            supportedVersions,
		random:                       make([]byte, 32),
		supportedCurves:              config.curvePreferences(version),
		secureRenegotiationSupported: true,
	}

	// 重协商需包含之前的 finished 消息一起计算
	if c.handshakes > 0 {
		hello.secureRenegotiation = c.localFinished[:]
	}

	// 基于硬件条件设置prefer order xx
	// cipherSuitesPreferenceOrder 是 cipher suite 的 id 列表
	preferenceOrder := cipherSuitesPreferenceOrder
	// if !hasAESGCMHardwareSupport {
	// 	preferenceOrder = cipherSuitesPreferenceOrderNoAES
	// }

	// configCipherSuites 如果没有特殊设置的话就会走默认，而默认就是 cipherSuitesPreferenceOrder
	// 所以和 preferenceOrder 是一致的
	// 两个套件id列表取交集然后放到 hello.cipherSuites 中
	configCipherSuites := config.cipherSuites()
	hello.cipherSuites = make([]uint16, 0, len(configCipherSuites))

	for _, suiteId := range preferenceOrder {
		suite := mutualCipherSuite(configCipherSuites, suiteId)
		if suite == nil {
			continue
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}

	// 生成随机数放到 hello.random 中
	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, errors.New("tls: short read from Rand: " + err.Error())
	}
	// 如果不是 tls1.3 hello 阶段无需生成 keyShareKeys
	// 主要工作就是确定好版本，密码套件这些信息【随机值目前是否有用还不清楚感觉不太需要】

	return hello, nil
}
