package e2ewebsocket

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"internal/byteorder"
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
	c               *Conn
	ctx             context.Context
	helloMsg        *helloMsg
	remoteHelloMsg  *helloMsg
	suite           *cipherSuite
	signatureScheme SignatureScheme
	finishedHash    finishedHash
	masterSecret    []byte
}

func (c *Conn) symHandshake(ctx context.Context) (err error) {

	if c.config == nil {
		c.config = defaultConfig()
	}

	// 【第一大步：生成本地 Hello 消息】
	hello, err := c.makeHello()
	if err != nil {
		return err
	}

	// 【第二大步：发送本地 Hello 消息】
	if _, err := c.writeHandshakeRecord(hello, nil); err != nil {
		return err
	}

	// 【第三大步：接收对端 Hello 消息】
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	remoteHello, ok := msg.(*helloMsg)
	if !ok {
		c.out.setErrorLocked(errors.New("alertUnexpectedMessage"))
		return errors.New("unexpectedMessageError")
	}

	// 选出来的版本直接记到 Conn 里面了
	if err := c.pickE2EVersion(remoteHello); err != nil {
		return err
	}

	// 后续如果改到 Session 下，相当于每个握手 Session 都有自己独立的 handshakeState
	hs := &handshakeState{
		c:              c,
		ctx:            ctx,
		helloMsg:       hello,
		remoteHelloMsg: remoteHello,
	}
	// 把自己构建发送的 hello 消息和接收的对端 hello 消息都挂在了 hs 上
	// 供后续 handshake 时 processHello 使用
	return hs.handshake()
}

func (c *Conn) makeHello() (*helloMsg, error) {

	config := c.config

	version := config.Version
	// 可通过 config 设置，没设置走默认
	if config.supportedVersions == nil {
		config.supportedVersions = config.defaultSupportedVersions()
	}

	if config.CurvePreferences == nil {
		config.CurvePreferences = config.curvePreferences(version)
	}

	// 可通过 config 设置，没设置走默认
	if config.SignatureSchemePreference == nil {
		config.SignatureSchemePreference = config.supportedSignatureAlgorithms()
	}

	if len(config.supportedVersions) == 0 || len(config.CurvePreferences) == 0 || len(config.SignatureSchemePreference) == 0 {
		return nil, errors.New("no supported versions or curves or signature schemes")
	}

	hello := &helloMsg{
		supportedVersions:            config.supportedVersions,
		random:                       make([]byte, 32),
		supportedCurves:              config.CurvePreferences,
		secureRenegotiationSupported: true,
		supportedSignatureAlgorithms: config.SignatureSchemePreference,
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
		suite := mutualCipherSuiteOld(configCipherSuites, suiteId)
		if suite == nil {
			continue
		}
		hello.cipherSuites = append(hello.cipherSuites, suiteId)
	}

	// 生成随机数放到 hello.random 中
	_, err := io.ReadFull(config.rand(), hello.random)
	if err != nil {
		return nil, errors.New("short read from Rand: " + err.Error())
	}
	// 如果不是 tls1.3 hello 阶段无需生成 keyShareKeys
	// 主要工作就是确定好版本，密码套件这些信息【随机值目前是否有用还不清楚感觉不太需要】

	return hello, nil
}

func (c *Conn) pickE2EVersion(remoteHello *helloMsg) error {
	vers, ok := c.config.mutualVersion(remoteHello.supportedVersions)
	if !ok {
		c.out.setErrorLocked(errors.New("alertProtocolVersion"))
		return fmt.Errorf("tls: server selected unsupported protocol version")
	}

	c.vers = vers
	c.in.version = vers
	c.out.version = vers

	return nil
}

func (hs *handshakeState) handshake() error {
	c := hs.c

	err := hs.processHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(hs.suite)

	if err := transcriptMsg(hs.helloMsg, &hs.finishedHash); err != nil {
		return err
	}
	if err := transcriptMsg(hs.remoteHelloMsg, &hs.finishedHash); err != nil {
		return err
	}

	if err := hs.doFullHandshake(); err != nil {
		return err
	}
	if err := hs.establishKeys(); err != nil {
		return err
	}
	if err := hs.sendFinished(c.localFinished[:]); err != nil {
		return err
	}

	// if _, err := c.flush(); err != nil {
	// 	return err
	// }

	// c.clientFinishedIsFirst = true
	// if err := hs.readSessionTicket(); err != nil {
	// 	return err
	// }

	if err := hs.readFinished(c.remoteFinished[:]); err != nil {
		return err
	}

	c.isHandshakeComplete.Store(true)

	return nil
}

func (hs *handshakeState) processHello() error {
	c := hs.c

	if err := hs.pickCipherSuite(); err != nil {
		return err
	}

	if err := hs.pickSignatureScheme(); err != nil {
		return err
	}

	if c.handshakes == 0 && hs.remoteHelloMsg.secureRenegotiationSupported {
		c.secureRenegotiation = true
		if len(hs.remoteHelloMsg.secureRenegotiation) != 0 {
			return c.out.setErrorLocked(errors.New("tls: initial handshake had non-empty renegotiation extension"))
		}
	}

	if c.handshakes > 0 && c.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], c.localFinished[:])
		copy(expectedSecureRenegotiation[12:], c.remoteFinished[:])
		if !bytes.Equal(hs.remoteHelloMsg.secureRenegotiation, expectedSecureRenegotiation[:]) {
			return c.out.setErrorLocked(errors.New("tls: incorrect renegotiation extension contents"))
		}
	}

	return nil
}

func (hs *handshakeState) pickCipherSuite() error {
	// 设置到 handshakeState 的 suite 和
	// Conn 的 cipherSuite 上
	if hs.suite = mutualCipherSuite(hs.helloMsg.cipherSuites, hs.remoteHelloMsg.cipherSuites); hs.suite == nil {
		return hs.c.out.setErrorLocked(errors.New("tls: server chose an unconfigured cipher suite"))
	}
	// todo: 如果是国密这里suite的ka要特殊构造
	hs.c.cipherSuite = hs.suite.id
	return nil
}

func (hs *handshakeState) pickSignatureScheme() error {

	if hs.signatureScheme = mutualSignatureScheme(hs.helloMsg.supportedSignatureAlgorithms, hs.remoteHelloMsg.supportedSignatureAlgorithms); hs.signatureScheme == 0 {
		return hs.c.out.setErrorLocked(errors.New("tls: server chose an unconfigured signature scheme"))
	}
	return nil
}

func (hs *handshakeState) doFullHandshake() error {
	// 要保证的是 hs 上的逻辑是统一的
	// 但是内部 ka 上的逻辑是不用统一的
	c := hs.c

	keyAgreement := hs.suite.ka

	// 先发自己的 keyExchangeMsg
	localKxm, err := keyAgreement.generateLocalKeyExchange(c.config, hs.helloMsg)
	if err != nil {
		c.out.setErrorLocked(errors.New("alertInternalError"))
		return err
	}
	if localKxm != nil {
		if _, err := hs.c.writeHandshakeRecord(localKxm, &hs.finishedHash); err != nil {
			return err
		}
	}

	// 在收对方的 keyExchangeMsg
	msg, err := c.readHandshake(&hs.finishedHash)
	if err != nil {
		return err
	}
	remoteKxm, ok := msg.(*keyExchangeMsg)
	var preMasterSecret []byte
	if ok {
		preMasterSecret, err = keyAgreement.processRemoteKeyExchange(c.config, hs.signatureScheme, hs.helloMsg, hs.remoteHelloMsg, remoteKxm)
		if err != nil {
			c.out.setErrorLocked(errors.New("alertIllegalParameter"))
			return err
		}
		// 获取曲线并记录
		if len(remoteKxm.key) >= 3 && remoteKxm.key[0] == 3 /* named curve */ {
			c.curveID = CurveID(byteorder.BEUint16(remoteKxm.key[1:]))
		}

	}

	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.helloMsg.random, hs.remoteHelloMsg.random)

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *handshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.helloMsg.random, hs.remoteHelloMsg.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var clientCipher, serverCipher any
	var clientHash, serverHash hash.Hash
	if hs.suite.cipher != nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, false /* not for reading */)
		clientHash = hs.suite.mac(clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, true /* for reading */)
		serverHash = hs.suite.mac(serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, serverCipher, serverHash)
	c.out.prepareCipherSpec(c.vers, clientCipher, clientHash)
	return nil
}

func (hs *handshakeState) sendFinished(out []byte) error {
	c := hs.c

	if err := c.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.localSum(hs.masterSecret)
	if _, err := hs.c.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

func (hs *handshakeState) readFinished(out []byte) error {
	c := hs.c

	if err := c.readChangeCipherSpec(); err != nil {
		return err
	}

	// finishedMsg is included in the transcript, but not until after we
	// check the client version, since the state before this message was
	// sent is used during verification.
	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		return c.out.setErrorLocked(errors.New("alertUnexpectedMessage"))
	}

	verify := hs.finishedHash.remoteSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		return c.out.setErrorLocked(errors.New("alertHandshakeFailure"))
	}

	if err := transcriptMsg(serverFinished, &hs.finishedHash); err != nil {
		return err
	}

	copy(out, verify)
	return nil
}
