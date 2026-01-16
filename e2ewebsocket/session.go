package e2ewebsocket

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"sync"
	"sync/atomic"

	ccrypto "github.com/albert/ws_client/crypto"
)

// Session: 负责单个逻辑会话的协商和加密
type Session struct {
	// 初始化时要填入的参数
	id       string
	remoteId string //【似乎可以不要】 因为 ws 里面记录了 hostId，所以 session 中记录对方的 id，避免出现需要从 id 里提取两个 id 的情况
	conn     *Conn

	// 协商确定的参数
	vers                uint16
	cipherSuite         uint16
	secureRenegotiation bool
	curveID             CurveID

	handshakes          int
	isHandshakeComplete atomic.Bool
	handshakeErr        error
	handshakeFn         func(context.Context) error
	handshakeMutex      sync.Mutex
	in, out             halfConn
	localFinished       [12]byte
	remoteFinished      [12]byte

	hand [][]byte
}

func NewSession(id string, remoteId string, conn *Conn) *Session {
	return &Session{
		id:       id,
		remoteId: remoteId,
		conn:     conn,
	}
}

func (s *Session) Handshake() error {
	return s.HandshakeContext(context.Background())
}

func (s *Session) HandshakeContext(ctx context.Context) error {
	return s.handshakeContext(ctx)
}

// 这些握手相关的，看起来应该挂到 Session 下而不是 Conn 下【Read Write 继续挂在 Conn 下】
func (s *Session) handshakeContext(ctx context.Context) (ret error) {

	if s.isHandshakeComplete.Load() {
		return nil
	}

	handshakeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 正常通过 Handshake 函数调用的，ctx 是 background 上下文不具有取消/超时逻辑
	// 不会有 ctx.Done() != nil 的情况
	if ctx.Done() != nil {

		done := make(chan struct{})
		interruptRes := make(chan error, 1)
		defer func() {
			// 该函数正常执行完后，会从 interruptRes 中拿错误
			// 如果之前 handshakeCtx 已经取消，拿到 handshakeCtx.Err() 错误
			// 如果之前 handshakeCtx 没有取消，函数正常执行完毕，那么会拿到 nil

			// [告诉中断器整个流程执行完毕]
			close(done)
			// [从中断器获取执行结果是正常执行了还是被打断了]
			if ctxErr := <-interruptRes; ctxErr != nil {
				// Return context error to user.
				ret = ctxErr
			}
		}()

		// 常见的是在主流程中for + select 监听ctx.Done()
		// 通过 default 不断推进函数正常工作内容
		// 这样上下文被取消的时候会及时打断主流程

		// 这种方式不会打断 handshakeContext 函数的正常执行
		// 但是提前 close 了 conn，执行过程中会出错
		// 最终再把 error 替换成 ctx 取消错误，代表是主动取消了握手

		// 开启一个 goroutine 中断器，监听 ctx.Done() 信号
		// 当 ctx 被取消时，关闭连接并返回 ctx.Err() 错误
		go func() {
			select {
			case <-handshakeCtx.Done():
				// Close the connection, discarding the error
				_ = s.conn.Close()
				interruptRes <- handshakeCtx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}
	// 【第三大步：上锁与二次状态检查】
	// 上锁并二次检查握手是否已经完成
	s.handshakeMutex.Lock()
	defer s.handshakeMutex.Unlock()

	if err := s.handshakeErr; err != nil {
		return err
	}
	if s.isHandshakeComplete.Load() {
		return nil
	}

	// 给 c.in 加锁，确保在握手过程中不会被其他 goroutine 访问
	// 握手过程涉及读写，加 in 锁是因为，read 和 write 上锁设计不同
	// 小 write 函数内部细粒度上锁，但是小 read 函数的不会上锁，所以都是在外部先上锁
	// 比如在这里进入握手状态机前，比如在大 Read 中上锁
	// s.in.Lock()
	// defer s.in.Unlock()
	// 【第四大步：执行握手】
	// 实际执行握手，返回 c.handshakeErr 握手错误
	s.handshakeErr = s.handshakeFn(handshakeCtx)
	if s.handshakeErr == nil {
		// 增加握手计数器
		s.handshakes++
	}

	// 握手没错但是标记未完成
	if s.handshakeErr == nil && !s.isHandshakeComplete.Load() {
		s.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}
	// 握手有错但是标记完成
	if s.handshakeErr != nil && s.isHandshakeComplete.Load() {
		panic("tls: internal error: handshake returned an error but is marked successful")
	}

	return s.handshakeErr
}

// 读两个

func (s *Session) readHandshake(transcript transcriptHash) (any, error) {

	// 合理应该弄一个最高上限次数，或者说超时时间，不能一致循环在这里
	// 其实感觉 readRecord 这个函数可能会有并发问题啊！是不是！
	for len(s.hand) == 0 {
		if err := s.conn.readRecord(); err != nil {
			return nil, err
		}
	}

	// 读取handshake数据
	data := s.hand[0]
	s.hand = s.hand[1:]

	maxHandshakeSize := maxHandshake

	// n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if len(data) > maxHandshakeSize {
		s.out.setErrorLocked(errors.New("alertInternalError"))
		return nil, s.in.setErrorLocked(fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", len(data), maxHandshakeSize))
	}

	return s.unmarshalHandshakeMessage(data, transcript)
}

func (s *Session) unmarshalHandshakeMessage(data []byte, transcript transcriptHash) (handshakeMessage, error) {
	// [1字节类型|和消息内容]
	// 无需长度
	var m handshakeMessage
	switch data[0] {
	case typeHelloMsg:
		m = new(helloMsg)
	// todo  补充其他消息
	default:
		return nil, s.in.setErrorLocked(s.out.setErrorLocked(errors.New("alertUnexpectedMessage")))
	}

	// 因为这里的原 data 其实来自 hand 缓冲区，所以为了不破坏 hand 缓冲区
	// 进行了一次非常地道的深拷贝
	// data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		return nil, s.in.setErrorLocked(s.out.setErrorLocked(errors.New("alertUnexpectedMessage")))
	}

	if transcript != nil {
		transcript.Write(data)
	}

	return m, nil
}

// 写两个个
func (s *Session) writeHandshakeRecord(msg handshakeMessage, transcript transcriptHash) error {
	// c.out.Lock()
	// defer c.out.Unlock()

	data, err := msg.marshal()
	if err != nil {
		return err
	}
	if transcript != nil {
		transcript.Write(data)
	}

	// 不论是写入握手消息还是应用消息，writeRecordLocked 前上 out 锁
	// writeRecordLocked 内部都会调用 out 加密
	return s.conn.writeRecordLocked(recordTypeHandshake, data, s)
}

func (s *Session) writeChangeCipherRecord() error {
	// c.out.Lock()
	// defer c.out.Unlock()
	err := s.conn.writeRecordLocked(recordTypeChangeCipherSpec, []byte{1}, s)
	return err
}

//  涉及重协商的这两个功能先不做
// func (s *Session) handlePostHandshakeMessage() error {

// 	return s.handleRenegotiation()

// }

// func (s *Session) handleRenegotiation() error {

// 	msg, err := s.conn.readHandshake(nil)
// 	if err != nil {
// 		return err
// 	}

// 	helloReq, ok := msg.(*helloRequestMsg)
// 	if !ok {
// 		s.sendAlert(alertUnexpectedMessage)
// 		return unexpectedMessageError(helloReq, msg)
// 	}

// 	if !s.conn.isClient {
// 		return s.sendAlert(alertNoRenegotiation)
// 	}

// 	switch s.config.Renegotiation {
// 	case RenegotiateNever:
// 		return s.sendAlert(alertNoRenegotiation)
// 	case RenegotiateOnceAsClient:
// 		if s.handshakes > 1 {
// 			return s.sendAlert(alertNoRenegotiation)
// 		}
// 	case RenegotiateFreelyAsClient:
// 		// Ok.
// 	default:
// 		s.sendAlert(alertInternalError)
// 		return errors.New("tls: unknown Renegotiation value")
// 	}

// 	s.handshakeMutex.Lock()
// 	defer s.handshakeMutex.Unlock()

// 	s.isHandshakeComplete.Store(false)
// 	if s.handshakeErr = s.clientHandshake(context.Background()); s.handshakeErr == nil {
// 		s.handshakes++
// 	}
// 	return s.handshakeErr
// }

type halfConn struct {
	// sync.Mutex
	err     error  // first permanent error
	version uint16 // protocol version
	cipher  any    // cipher algorithm
	mac     hash.Hash
	seq     [8]byte // 64-bit sequence number

	scratchBuf [13]byte // to avoid allocs; interface method args escape

	nextCipher any       // next encryption state
	nextMac    hash.Hash // next MAC algorithm
}

func (hc *halfConn) decrypt(payload []byte) ([]byte, error) {

	// 我传进来的整个都是 payload 不是带 header 的 record
	var plaintext []byte

	explicitNonceLen := hc.explicitNonceLen()

	if hc.cipher != nil {
		switch c := hc.cipher.(type) {
		case cipher.Stream:
			c.XORKeyStream(payload, payload)
		case ccrypto.AEAD:

			if len(payload) < explicitNonceLen {
				return nil, errors.New("alertBadRecordMAC")
			}
			nonce := payload[:explicitNonceLen]
			if len(nonce) == 0 {
				// nonce = hc.seq[:]
				return nil, errors.New("alertNonceZero")
			}
			payload = payload[explicitNonceLen:]

			// 构造 additionalData
			var additionalData []byte
			// 这个 13 字节的 scratchBuf 设计以及 scratchBuf[:0] 操作是很秀的
			// additionalData 变量底层指向的是 scratchBuf 指向的数组
			additionalData = append(hc.scratchBuf[:0], hc.seq[:]...)
			n := len(payload) - c.Overhead()
			additionalData = append(additionalData, byte(n>>8), byte(n))

			var err error
			plaintext, err = c.Open(payload[:0], nonce, payload, additionalData)
			if err != nil {
				return nil, errors.New("alertBadRecordMAC")
			}
		// case cbcMode:
		// TODO:
		// blockSize := c.BlockSize()
		// minPayload := explicitNonceLen + roundUp(hc.mac.Size()+1, blockSize)
		// if len(payload)%blockSize != 0 || len(payload) < minPayload {
		// 	return nil, 0, alertBadRecordMAC
		// }

		// if explicitNonceLen > 0 {
		// 	c.SetIV(payload[:explicitNonceLen])
		// 	payload = payload[explicitNonceLen:]
		// }
		// c.CryptBlocks(payload, payload)

		// // In a limited attempt to protect against CBC padding oracles like
		// // Lucky13, the data past paddingLen (which is secret) is passed to
		// // the MAC function as extra data, to be fed into the HMAC after
		// // computing the digest. This makes the MAC roughly constant time as
		// // long as the digest computation is constant time and does not
		// // affect the subsequent write, modulo cache effects.
		// paddingLen, paddingGood = extractPadding(payload)
		default:
			panic("unknown cipher type")
		}

	} else {
		plaintext = payload
	}

	if hc.mac != nil {
		// TODO:

		// macSize := hc.mac.Size()
		// if len(payload) < macSize {
		// 	return nil, 0, alertBadRecordMAC
		// }

		// n := len(payload) - macSize - paddingLen
		// n = subtle.ConstantTimeSelect(int(uint32(n)>>31), 0, n) // if n < 0 { n = 0 }
		// record[3] = byte(n >> 8)
		// record[4] = byte(n)
		// remoteMAC := payload[n : n+macSize]
		// localMAC := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload[:n], payload[n+macSize:])

		// // This is equivalent to checking the MACs and paddingGood
		// // separately, but in constant-time to prevent distinguishing
		// // padding failures from MAC failures. Depending on what value
		// // of paddingLen was returned on bad padding, distinguishing
		// // bad MAC from bad padding can lead to an attack.
		// //
		// // See also the logic at the end of extractPadding.
		// macAndPaddingGood := subtle.ConstantTimeCompare(localMAC, remoteMAC) & int(paddingGood)
		// if macAndPaddingGood != 1 {
		// 	return nil, 0, alertBadRecordMAC
		// }

		// plaintext = payload[:n]
	}

	hc.incSeq()
	return plaintext, nil
}

func (hc *halfConn) encrypt(record, payload []byte, rand io.Reader) ([]byte, error) {
	if hc.cipher == nil {
		return append(record, payload...), nil
	}

	var explicitNonce []byte
	if explicitNonceLen := hc.explicitNonceLen(); explicitNonceLen > 0 {
		record, explicitNonce = sliceForAppend(record, explicitNonceLen)
		if _, isCBC := hc.cipher.(ccrypto.CBCMode); !isCBC && explicitNonceLen < 16 {
			// The AES-GCM construction in TLS has an explicit nonce so that the
			// nonce can be random. However, the nonce is only 8 bytes which is
			// too small for a secure, random nonce. Therefore we use the
			// sequence number as the nonce. The 3DES-CBC construction also has
			// an 8 bytes nonce but its nonces must be unpredictable (see RFC
			// 5246, Appendix F.3), forcing us to use randomness. That's not
			// 3DES' biggest problem anyway because the birthday bound on block
			// collision is reached first due to its similarly small block size
			// (see the Sweet32 attack).
			copy(explicitNonce, hc.seq[:])
		} else {
			if _, err := io.ReadFull(rand, explicitNonce); err != nil {
				return nil, err
			}
		}
	}

	switch c := hc.cipher.(type) {
	// case cipher.Stream:
	// 	mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
	// 	record, dst = sliceForAppend(record, len(payload)+len(mac))
	// 	c.XORKeyStream(dst[:len(payload)], payload)
	// 	c.XORKeyStream(dst[len(payload):], mac)
	case ccrypto.AEAD:
		nonce := explicitNonce
		if len(nonce) == 0 {
			nonce = hc.seq[:]
		}
		additionalData := append(hc.scratchBuf[:0], hc.seq[:]...)
		// additionalData = append(additionalData,record[:1]...)
		additionalData = append(additionalData, byte(len(payload)>>8), byte(len(payload)))
		record = c.Seal(record, nonce, payload, additionalData)

	// case cbcMode:
	// 	mac := tls10MAC(hc.mac, hc.scratchBuf[:0], hc.seq[:], record[:recordHeaderLen], payload, nil)
	// 	blockSize := c.BlockSize()
	// 	plaintextLen := len(payload) + len(mac)
	// 	paddingLen := blockSize - plaintextLen%blockSize
	// 	record, dst = sliceForAppend(record, plaintextLen+paddingLen)
	// 	copy(dst, payload)
	// 	copy(dst[len(payload):], mac)
	// 	for i := plaintextLen; i < len(dst); i++ {
	// 		dst[i] = byte(paddingLen - 1)
	// 	}
	// 	if len(explicitNonce) > 0 {
	// 		c.SetIV(explicitNonce)
	// 	}
	// 	c.CryptBlocks(dst, dst)
	default:
		panic("unknown cipher type")
	}

	// Update length to include nonce, MAC and any block padding needed.
	hc.incSeq()

	return record, nil
}

func (hc *halfConn) prepareCipherSpec(version uint16, cipher any, mac hash.Hash) {
	hc.version = version
	hc.nextCipher = cipher
	hc.nextMac = mac
}

func (hc *halfConn) changeCipherSpec() error {
	if hc.nextCipher == nil {
		return errors.New("alertInternalError")
	}
	hc.cipher = hc.nextCipher
	hc.mac = hc.nextMac
	hc.nextCipher = nil
	hc.nextMac = nil
	// 将64位序列号seq重置为全0
	// 这是TLS协议要求的，确保新的加密状态使用新的序列号计数
	for i := range hc.seq {
		hc.seq[i] = 0
	}
	return nil
}

// =======================================================
func (hc *halfConn) explicitNonceLen() int {
	if hc.cipher == nil {
		return 0
	}

	// any 类型的 cipher可以是 cipher.Stream, aead, cbcMode 这三种 interface
	// 其中 aead 是在 cipher.AEAD 基础上改的
	// 这里的 cbcMode 是在 cipher.BlockMode 基础上改的
	switch c := hc.cipher.(type) {
	case cipher.Stream:
		return 0
	case ccrypto.AEAD:
		return c.ExplicitNonceLen()
	// case cbcMode:
	// 	// TLS 1.1 introduced a per-record explicit IV to fix the BEAST attack.
	// 	if hc.version >= VersionTLS11 {
	// 		return c.BlockSize()
	// 	}
	// 	return 0
	default:
		panic("unknown cipher type")
	}
}

func (hc *halfConn) incSeq() {
	// 64位无符号序列号的安全递增操作
	// 从最低位开始加1，如果不发生进位则直接结束
	// 发生进位时，继续向高位递增，直到没有进位或到达最高位
	for i := 7; i >= 0; i-- {
		hc.seq[i]++
		if hc.seq[i] != 0 {
			return
		}
	}

	// Not allowed to let sequence number wrap.
	// Instead, must renegotiate before it does.
	// Not likely enough to bother.
	panic("TLS: sequence number wraparound")
}

type permanentError struct {
	err net.Error
}

func (e *permanentError) Error() string   { return e.err.Error() }
func (e *permanentError) Unwrap() error   { return e.err }
func (e *permanentError) Timeout() bool   { return e.err.Timeout() }
func (e *permanentError) Temporary() bool { return false }

func (hc *halfConn) setErrorLocked(err error) error {
	if e, ok := err.(net.Error); ok {
		hc.err = &permanentError{err: e}
	} else {
		hc.err = err
	}
	return hc.err
}
