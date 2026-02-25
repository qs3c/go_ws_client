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

type SessionID string

type sessionMsg struct {
	typ  recordType
	data []byte
	err  error
}

type Session struct {
	// 初始化时要填入的参数
	id       SessionID
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

	handshakeChan chan sessionMsg

	done              chan struct{}
	handshakeComplete chan struct{} // 通知握手完成，替代 polling
	closeOnce         sync.Once
}

func NewSession(id SessionID, remoteId string, conn *Conn) *Session {
	s := &Session{
		id:                id,
		remoteId:          remoteId,
		conn:              conn,
		handshakeChan:     make(chan sessionMsg, 16),
		done:              make(chan struct{}),
		handshakeComplete: make(chan struct{}, 1),
	}
	s.in.session = s
	s.out.session = s
	s.in.nextCipherReady = make(chan struct{}, 1)
	s.out.nextCipherReady = make(chan struct{}, 1)
	s.handshakeFn = s.symHandshake
	return s
}

func (s *Session) Handshake() error {
	return s.HandshakeContext(context.Background())
}

func (s *Session) HandshakeContext(ctx context.Context) error {
	return s.handshakeContext(ctx)
}

func (s *Session) handshakeContext(ctx context.Context) (ret error) {

	if s.isHandshakeComplete.Load() {
		return nil
	}

	s.handshakeMutex.Lock()
	defer s.handshakeMutex.Unlock()

	// 如果之前的握手是失败的，那么不能进行下一次握手
	if err := s.handshakeErr; err != nil {
		return err
	}
	if s.isHandshakeComplete.Load() {
		return nil
	}

	// 不同的 session 之间握手读写冲突问题
	s.handshakeErr = s.handshakeFn(ctx)
	if s.handshakeErr == nil {
		s.handshakes++
	}

	// 握手没错但是标记未完成
	if s.handshakeErr == nil && !s.isHandshakeComplete.Load() {
		s.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}
	// 握手有错但是标记完成
	if s.handshakeErr != nil && s.isHandshakeComplete.Load() {
		// panic("tls: internal error: handshake returned an error but is marked successful")
		return fmt.Errorf("tls: internal error: handshake returned an error (%v) but is marked successful", s.handshakeErr)
	}

	return s.handshakeErr
}

func (s *Session) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
		// 唤醒所有等待者，让它们有机会检查 done channel 并退出
		// s.in.cond.Broadcast()
		// s.out.cond.Broadcast()
	})
}

func (s *Session) readHandshake(transcript transcriptHash) (any, error) {

	// ################## 什么情况导致close，close了应该怎么办
	var msg sessionMsg
	var ok bool
	select {
	case msg, ok = <-s.handshakeChan:
		if !ok {
			return nil, errors.New("handshake channel closed")
		}
	case <-s.done:
		return nil, errors.New("session closed")
	}

	// 校验数据长度
	data := msg.data
	maxHandshakeSize := maxHandshake
	if len(data) > maxHandshakeSize {
		return nil, fmt.Errorf("handshake message of length %d bytes exceeds maximum of %d bytes", len(data), maxHandshakeSize)
	}

	return s.unmarshalHandshakeMessage(data, transcript)
}

// 新的读写架构下，不需要了
// func (s *Session) readChangeCipherSpec() error {}

// marshal 是各种不同结构的都 marshal 成一样的 []byte
// unmarshal 是把 []byte 转换成各种不同的结构，调用谁的 unmarshal 你不知道
// 所以需要根据 data[0] 来判断调用谁的 unmarshal 所以比 marshal 多了一步
func (s *Session) unmarshalHandshakeMessage(data []byte, transcript transcriptHash) (handshakeMessage, error) {
	// [1字节类型|和消息内容]
	// 无需长度
	var m handshakeMessage
	switch data[0] {
	case typeHelloMsg:
		m = new(helloMsg)
	case typeKeyExchange:
		m = new(keyExchangeMsg)
	case typeFinished:
		m = new(finishedMsg)
	default:
		// return nil, s.in.setErrorLocked(s.out.setErrorLocked(errors.New("alertUnexpectedMessage")))
		return nil, errors.New("alertUnexpectedMessage")
	}

	// 因为这里的原 data 其实来自 hand 缓冲区，所以为了不破坏 hand 缓冲区
	// 进行了一次非常地道的深拷贝
	// data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		// return nil, s.in.setErrorLocked(s.out.setErrorLocked(errors.New("alertUnexpectedMessage")))
		return nil, errors.New("alertUnexpectedMessage")
	}

	if transcript != nil {
		transcript.Write(data)
	}

	return m, nil
}

func (s *Session) writeHandshakeRecord(msg handshakeMessage, transcript transcriptHash) error {

	data, err := msg.marshal()
	if err != nil {
		return err
	}
	if transcript != nil {
		transcript.Write(data)
	}

	return s.conn.writeRecordLocked(recordTypeHandshake, data, s)
}

func (s *Session) writeChangeCipherRecord() error {
	err := s.conn.writeRecordLocked(recordTypeChangeCipherSpec, []byte{1}, s)
	if err != nil {
		return err
	}
	return s.out.changeCipherSpec()
}

type halfConn struct {
	sync.Mutex
	err     error  // first permanent error
	version uint16 // protocol version
	cipher  any    // cipher algorithm
	mac     hash.Hash
	seq     [8]byte // 64-bit sequence number

	scratchBuf [13]byte // to avoid allocs; interface method args escape

	nextCipher any       // next encryption state
	nextMac    hash.Hash // next MAC algorithm

	nextCipherReady chan struct{}

	// Fields added for session simplification
	session *Session
}

// ++++++++++++++++++++++++待改++++++++++++++++++++++++++++++
func (hc *halfConn) decrypt(payload []byte) ([]byte, error) {
	// ################# 有必要吗
	hc.Lock()
	defer hc.Unlock()

	var plaintext []byte

	explicitNonceLen := hc.explicitNonceLen()

	if hc.cipher != nil {
		switch c := hc.cipher.(type) {
		case cipher.Stream:
			c.XORKeyStream(payload, payload)
		case ccrypto.AEAD:

			// 分离 nonce 和 payload
			if len(payload) < explicitNonceLen {
				return nil, errors.New("alertBadRecordMAC")
			}
			nonce := payload[:explicitNonceLen]
			if len(nonce) == 0 {
				// nonce = hc.seq[:]
				return nil, errors.New("alertNonceZero")
			}
			payload = payload[explicitNonceLen:]
			if len(payload) < c.Overhead() {
				return nil, errors.New("alertBadRecordMAC")
			}

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
		default:
			panic("unknown cipher type")
		}

	} else {
		plaintext = payload
	}

	if hc.mac != nil {
		// TODO:
	}

	hc.incSeq()
	return plaintext, nil
}

func (hc *halfConn) encrypt(record, payload []byte, rand io.Reader) ([]byte, error) {
	hc.Lock()
	defer hc.Unlock()
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
	// 	TODO:
	default:
		panic("unknown cipher type")
	}

	// Update length to include nonce, MAC and any block padding needed.
	hc.incSeq()

	return record, nil
}

// 根据密钥协商后派生密钥产生的结果，把下次要切换的密码套件设置好
func (hc *halfConn) prepareCipherSpec(version uint16, cipher any, mac hash.Hash) {
	// ############保护半连接的字段修改【有必要吗这里】
	hc.Lock()
	defer hc.Unlock()
	hc.version = version
	hc.nextCipher = cipher
	hc.nextMac = mac
	// PCS 完成通知 CCS
	select {
	case hc.nextCipherReady <- struct{}{}:
	default:
	}
}

// 切换到 prepare 设置的 cipher，并把下一次的密码套件置 nil
// 直到下次握手=>协商产生密钥=> prepare 之后方可 change 切换
func (hc *halfConn) changeCipherSpec() error {
	hc.Lock()
	defer hc.Unlock()

	// 虽然 prepareCipherSpec 会在设置 nextCipher 后发送信号
	// 但为了避免死锁，我们必须在等待信号前释放锁
	// 因为 prepareCipherSpec 也需要获取锁才能设置 nextCipher
	if hc.nextCipher == nil {
		hc.Unlock()
		// 检查是否 session 已关闭
		select {
		case <-hc.session.done:
			hc.Lock() // 重新加锁以保证 defer Unlock 正常执行（虽然这里要返回error了，但为了defer安全性）
			return errors.New("session closed")
		case <-hc.nextCipherReady:
		}
		hc.Lock()
	}

	if hc.nextCipher == nil {
		return errors.New("alertInternalError")
	}
	hc.cipher = hc.nextCipher
	hc.mac = hc.nextMac
	hc.nextCipher = nil
	hc.nextMac = nil
	// 将 64 位序列号 seq 重置为全 0
	// 这是 TLS 协议要求的，确保新的加密状态使用新的序列号计数
	// 换密码套件了 seq 重新计数
	// 不换的时候每次加解密时都增加计数
	// in 和 out 各有各的计数
	for i := range hc.seq {
		hc.seq[i] = 0
	}
	return nil
}

func (hc *halfConn) explicitNonceLen() int {
	if hc.cipher == nil {
		return 0
	}

	switch c := hc.cipher.(type) {
	case cipher.Stream:
		return 0
	case ccrypto.AEAD:
		return c.ExplicitNonceLen()
	// case cbcMode:
	//	return c.BlockSize()

	default:
		panic("unknown cipher type")
	}
}

// 64位序列号自增，每次加密/解密成功后调用
// hc.seq 一般作为 aead 中的 additional data 的部分起到校验的作用
// 有时也作为 nonce
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
	panic("sequence number wraparound")
}

type permanentError struct {
	err net.Error
}

func (e *permanentError) Error() string   { return e.err.Error() }
func (e *permanentError) Unwrap() error   { return e.err }
func (e *permanentError) Timeout() bool   { return e.err.Timeout() }
func (e *permanentError) Temporary() bool { return false }
