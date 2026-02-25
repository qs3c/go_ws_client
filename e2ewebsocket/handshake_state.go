package e2ewebsocket

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"hash"
	"io"
	"path/filepath"

	ccrypto "github.com/albert/ws_client/crypto"
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
	// c *Conn
	s *Session

	localId  string
	remoteId string

	helloMsg        *helloMsg
	remoteHelloMsg  *helloMsg
	suite           *cipherSuite
	signatureScheme SignatureScheme
	finishedHash    finishedHash
	masterSecret    []byte
}

// 原先的三个来在 conn 的过渡方法现在要归属于 session 了
func (s *Session) symHandshake(ctx context.Context) (err error) {

	if s.conn.config == nil {
		s.conn.config = defaultConfig()
	}

	// 【第一大步：生成本地 Hello 消息】
	hello, err := s.makeHello()
	if err != nil {
		return err
	}

	// 【第二大步：发送本地 Hello 消息】
	if err := s.writeHandshakeRecord(hello, nil); err != nil {
		return err
	}

	// 【第三大步：接收对端 Hello 消息】
	msg, err := s.readHandshake(nil)
	if err != nil {
		return err
	}

	remoteHello, ok := msg.(*helloMsg)
	if !ok {
		// s.out.setErrorLocked(errors.New("alertUnexpectedMessage"))
		// s.SetError(errors.New("unexpectedMessageError"))
		return errors.New("unexpectedMessageError")
	}

	// 选出来的版本直接记到 Conn 里面了
	if err := s.pickE2EVersion(remoteHello); err != nil {
		return err
	}

	// 后续如果改到 Session 下，相当于每个握手 Session 都有自己独立的 handshakeState
	hs := &handshakeState{
		s:              s,
		helloMsg:       hello,
		remoteHelloMsg: remoteHello,

		localId:  s.conn.hostId,
		remoteId: s.remoteId,
	}
	// 把自己构建发送的 hello 消息和接收的对端 hello 消息都挂在了 hs 上
	// 供后续 handshake 时 processHello 使用
	return hs.handshake()
}

func (s *Session) makeHello() (*helloMsg, error) {

	config := s.conn.config

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
	if s.handshakes > 0 {
		hello.secureRenegotiation = s.localFinished[:]
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

func (s *Session) pickE2EVersion(remoteHello *helloMsg) error {
	vers, ok := s.conn.config.mutualVersion(remoteHello.supportedVersions)
	if !ok {
		// s.out.setErrorLocked(errors.New("alertProtocolVersion"))
		// s.SetError(errors.New("protocolVersionError"))
		return fmt.Errorf("server selected unsupported protocol version")
	}

	s.vers = vers
	s.in.version = vers
	s.out.version = vers

	return nil
}

func (hs *handshakeState) handshake() error {
	s := hs.s

	err := hs.processHello()
	if err != nil {
		return err
	}

	hs.finishedHash = newFinishedHash(hs.suite, hs.localId, hs.remoteId)

	// 统一按 initiator(ID大) 先写、responder 后写，确保双方 hash 相同
	if hs.localId > hs.remoteId {
		// 本方是 initiator
		if err := transcriptMsg(hs.helloMsg, &hs.finishedHash); err != nil {
			return err
		}
		if err := transcriptMsg(hs.remoteHelloMsg, &hs.finishedHash); err != nil {
			return err
		}
	} else {
		// 本方是 responder
		if err := transcriptMsg(hs.remoteHelloMsg, &hs.finishedHash); err != nil {
			return err
		}
		if err := transcriptMsg(hs.helloMsg, &hs.finishedHash); err != nil {
			return err
		}
	}

	if err := hs.doFullHandshake(); err != nil {
		return err
	}
	if err := hs.establishKeys(); err != nil {
		return err
	}
	if err := hs.sendFinished(s.localFinished[:]); err != nil {
		return err
	}

	// if _, err := c.flush(); err != nil {
	// 	return err
	// }

	// c.clientFinishedIsFirst = true
	// if err := hs.readSessionTicket(); err != nil {
	// 	return err
	// }

	if err := hs.readFinished(s.remoteFinished[:]); err != nil {
		return err
	}

	// 标记握手已完成
	s.isHandshakeComplete.Store(true)

	// 发送通知握手完成（非阻塞），替代 close，以便支持重协商
	select {
	case s.handshakeComplete <- struct{}{}:
	default:
		// 如果没人听就丢弃
		// 反正 isHandshakeComplete 已经置 true 了
	}

	return nil
}

func (hs *handshakeState) processHello() error {
	s := hs.s

	if err := hs.pickCipherSuite(); err != nil {
		return err
	}

	if err := hs.pickSignatureScheme(); err != nil {
		return err
	}

	if s.handshakes == 0 && hs.remoteHelloMsg.secureRenegotiationSupported {
		s.secureRenegotiation = true
		if len(hs.remoteHelloMsg.secureRenegotiation) != 0 {
			// return s.out.setErrorLocked(errors.New("tls: initial handshake had non-empty renegotiation extension"))
			return errors.New("initialHandshakeError")
		}
	}

	if s.handshakes > 0 && s.secureRenegotiation {
		var expectedSecureRenegotiation [24]byte
		copy(expectedSecureRenegotiation[:], s.localFinished[:])
		copy(expectedSecureRenegotiation[12:], s.remoteFinished[:])
		if !bytes.Equal(hs.remoteHelloMsg.secureRenegotiation, expectedSecureRenegotiation[:]) {
			// return s.out.setErrorLocked(errors.New("tls: incorrect renegotiation extension contents"))
			return errors.New("incorrectRenegotiationError")
		}
	}

	return nil
}

func (hs *handshakeState) pickCipherSuite() error {
	// 设置到 handshakeState 的 suite 和
	// Conn 的 cipherSuite 上
	if hs.suite = mutualCipherSuite(hs.helloMsg.cipherSuites, hs.remoteHelloMsg.cipherSuites); hs.suite == nil {
		// return hs.s.out.setErrorLocked(errors.New("tls: server chose an unconfigured cipher suite"))
		return errors.New("unconfiguredCipherSuiteError")
	}
	// todo: 如果是国密这里suite的ka要特殊构造(也不一定要在这里)
	// if sm2ka, ok := hs.suite.ka.(*sm2KeyAgreement); ok {
	// 	sm2ka.localId = hs.localId
	// 	sm2ka.remoteId = hs.remoteId
	// }
	hs.s.cipherSuite = hs.suite.id
	return nil
}

func (hs *handshakeState) pickSignatureScheme() error {

	if hs.signatureScheme = mutualSignatureScheme(hs.helloMsg.supportedSignatureAlgorithms, hs.remoteHelloMsg.supportedSignatureAlgorithms); hs.signatureScheme == 0 {
		// return hs.s.out.setErrorLocked(errors.New("tls: server chose an unconfigured signature scheme"))
		return errors.New("unconfiguredSignatureSchemeError")
	}
	return nil
}

func (hs *handshakeState) doFullHandshake() error {
	// 要保证的是 hs 上的逻辑是统一的
	// 但是内部 ka 上的逻辑是不用统一的
	s := hs.s

	// 必须为当前握手创建一个新实例（副本），
	// 因为它包含 session 特有的状态（localId, remoteId, keys, ctxLocal 等）。
	// 原 suite.ka 是全局单例，不能直接修改。
	var keyAgreement keyAgreement

	switch hs.suite.ka.(type) {
	case *sm2KeyAgreement:
		// 加载密钥
		localPrivateKey, err := ccrypto.LoadPrivateKeyFileFromPEM(filepath.Join(s.conn.config.keyStorePath(), hs.localId, "private_key.pem"))
		if err != nil {
			return err
		}
		remotePublicKey, err := ccrypto.LoadPublicKeyFileFromPEM(filepath.Join(s.conn.config.keyStorePath(), hs.remoteId, "public_key.pem"))
		if err != nil {
			return err
		}

		// 创建新的 SM2 KeyAgreement 实例
		// 使用 NewSM2KeyAgreement 构造函数来初始化内部的 KAPCtx 等
		newKA := NewSM2KeyAgreement(localPrivateKey, hs.localId, remotePublicKey, hs.remoteId)
		if newKA == nil {
			return errors.New("failed to initialize SM2 Key Agreement")
		}
		keyAgreement = newKA
	default:
		return fmt.Errorf("internal error: unsupported key agreement type: %T", hs.suite.ka)
	}
	// 先发自己的 keyExchangeMsg
	localKxm, err := keyAgreement.generateLocalKeyExchange(s.conn.config, hs.signatureScheme, hs.helloMsg, hs.remoteHelloMsg)
	if err != nil {
		// s.out.setErrorLocked(errors.New("alertInternalError"))
		// s.SetError(errors.New("alertInternalError"))
		return err
	}
	if localKxm != nil {
		// 统一按 initiator(ID大) 先写入 transcript
		if hs.localId > hs.remoteId {
			// 本方是 initiator，直接写自己的 kxm 到 transcript
			if err := s.writeHandshakeRecord(localKxm, &hs.finishedHash); err != nil {
				return err
			}
		} else {
			// 本方是 responder，先发送但不写 transcript（等读到 initiator kxm 后再统一）
			if err := s.writeHandshakeRecord(localKxm, nil); err != nil {
				return err
			}
		}
	}

	// 再收对方的 keyExchangeMsg
	msg, err := s.readHandshake(nil) // 不写 transcript，手动控制顺序
	if err != nil {
		return err
	}
	remoteKxm, ok := msg.(*keyExchangeMsg)

	// 统一写 kxm 到 transcript：initiator 先，responder 后
	if ok {
		if hs.localId > hs.remoteId {
			// 本方是 initiator：写对方(responder)的 kxm
			if err := transcriptMsg(remoteKxm, &hs.finishedHash); err != nil {
				return err
			}
		} else {
			// 本方是 responder：先写 initiator(对方) kxm，再写自己(responder) kxm
			if err := transcriptMsg(remoteKxm, &hs.finishedHash); err != nil {
				return err
			}
			if err := transcriptMsg(localKxm, &hs.finishedHash); err != nil {
				return err
			}
		}
	}

	var preMasterSecret []byte
	if ok {
		preMasterSecret, err = keyAgreement.processRemoteKeyExchange(s.conn.config, hs.signatureScheme, hs.helloMsg, hs.remoteHelloMsg, remoteKxm)
		if err != nil {
			return err
		}
		// 获取曲线并记录
		if len(remoteKxm.key) >= 3 && remoteKxm.key[0] == 3 /* named curve */ {
			s.curveID = CurveID(BEUint16(remoteKxm.key[1:]))
		}
	}

	// sm2 的 initiator 逻辑影响到了外面，hs得有状态记录
	// 统一排序：initiator(ID大的一方)的random在前，responder的在后
	var initiatorRandom, responderRandom []byte
	if hs.localId > hs.remoteId {
		initiatorRandom = hs.helloMsg.random
		responderRandom = hs.remoteHelloMsg.random
	} else {
		initiatorRandom = hs.remoteHelloMsg.random
		responderRandom = hs.helloMsg.random
	}
	hs.masterSecret = masterFromPreMasterSecret(s.vers, hs.suite, preMasterSecret, initiatorRandom, responderRandom)

	// hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *handshakeState) establishKeys() error {
	s := hs.s
	// 到这里你就发现sm2影响的不是只ka内部的逻辑了
	// 甚至是影响到了外面，这里关于keys的生成

	// 统一排序：initiator(ID大的一方)的random在前
	var initiatorRandom, responderRandom []byte
	if hs.localId > hs.remoteId {
		initiatorRandom = hs.helloMsg.random
		responderRandom = hs.remoteHelloMsg.random
	} else {
		initiatorRandom = hs.remoteHelloMsg.random
		responderRandom = hs.helloMsg.random
	}

	initiatorMAC, responderMAC, initiatorKey, responderKey, initiatorIV, responderIV :=
		keysFromMasterSecret(s.vers, hs.suite, hs.masterSecret, initiatorRandom, responderRandom, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)
	var initiatorCipher, responderCipher any
	var initiatorHash, responderHash hash.Hash
	if hs.suite.cipher != nil {
		initiatorCipher = hs.suite.cipher(initiatorKey, initiatorIV, false /* not for reading */)
		initiatorHash = hs.suite.mac(initiatorMAC)
		responderCipher = hs.suite.cipher(responderKey, responderIV, true /* for reading */)
		responderHash = hs.suite.mac(responderMAC)
	} else {
		initiatorCipher = hs.suite.aead(initiatorKey, initiatorIV)
		responderCipher = hs.suite.aead(responderKey, responderIV)
	}

	// initiator 的 out 用 initiatorCipher, in 用 responderCipher
	// responder 的 out 用 responderCipher, in 用 initiatorCipher
	if hs.localId > hs.remoteId {
		// 本方是 initiator
		s.in.prepareCipherSpec(s.vers, responderCipher, responderHash)
		s.out.prepareCipherSpec(s.vers, initiatorCipher, initiatorHash)
	} else {
		// 本方是 responder
		s.in.prepareCipherSpec(s.vers, initiatorCipher, initiatorHash)
		s.out.prepareCipherSpec(s.vers, responderCipher, responderHash)
	}
	return nil
}

func (hs *handshakeState) sendFinished(out []byte) error {
	s := hs.s

	if err := s.writeChangeCipherRecord(); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.localSum(hs.masterSecret)
	if err := s.writeHandshakeRecord(finished, &hs.finishedHash); err != nil {
		return err
	}
	copy(out, finished.verifyData)
	return nil
}

func (hs *handshakeState) readFinished(out []byte) error {
	s := hs.s

	// if err := s.conn.readChangeCipherSpec(); err != nil {
	// 	return err
	// }

	msg, err := s.readHandshake(nil)
	if err != nil {
		return err
	}
	serverFinished, ok := msg.(*finishedMsg)
	if !ok {
		// return s.out.setErrorLocked(errors.New("alertUnexpectedMessage"))
		return errors.New("alertUnexpectedMessage")
	}

	verify := hs.finishedHash.remoteSum(hs.masterSecret)
	if len(verify) != len(serverFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, serverFinished.verifyData) != 1 {
		// return s.out.setErrorLocked(errors.New("alertHandshakeFailure"))
		return errors.New("alertHandshakeFailure")
	}

	// 结算之后才计入哈希
	if err := transcriptMsg(serverFinished, &hs.finishedHash); err != nil {
		return err
	}

	copy(out, verify)
	return nil
}
