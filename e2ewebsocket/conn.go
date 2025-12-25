package e2ewebsocket

import (
	"bytes"
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"hash"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/albert/ws_client/crypto/sm4tongsuo"
	"github.com/gorilla/websocket"
)

type Conn struct {
	conn websocket.Conn

	vers        uint16
	cipherSuite uint16

	secureRenegotiation bool

	activeCall atomic.Int32

	curveID CurveID

	closeNotifyErr  error
	closeNotifySent bool

	handshakes          int
	isHandshakeComplete atomic.Bool
	handshakeErr        error
	handshakeFn         func(context.Context) error
	handshakeMutex      sync.Mutex

	in, out halfConn

	input bytes.Reader
	hand  bytes.Buffer

	config *Config

	localFinished  [12]byte
	remoteFinished [12]byte
}

// websocket.Conn 没有实现 net.Conn 接口
// var _ net.Conn = websocket.Conn{}

func (c *Conn) Read(b []byte) (int, error) {
	// 握手检查
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	// 入参检查，放在 Handshake 之后以支持 Read(nil) 仅触发握手的场景
	if len(b) == 0 {
		// Put this after Handshake, in case people were calling
		// Read(nil) for the side effect of the Handshake.
		return 0, nil
	}

	// 输入锁
	c.in.Lock()
	defer c.in.Unlock()

	// rawInput 未解密原始输入缓冲区（TLS 记录缓冲区）
	// 当输已解密的入缓冲区 input 为空时，读取新的已解密的 TLS 记录
	// 当握手数据缓冲区 hand 不为空时，处理可能的握手后消息（如证书请求、密钥更新等）
	for c.input.Len() == 0 {
		if err := c.readRecord(); err != nil {
			return 0, err
		}
		for c.hand.Len() > 0 {
			if err := c.handlePostHandshakeMessage(); err != nil {
				return 0, err
			}
		}
	}

	// 从解密后的应用数据输入缓冲区 input 读取数据
	n, _ := c.input.Read(b)

	// If a close-notify alert is waiting, read it so that we can return (n,
	// EOF) instead of (n, nil), to signal to the HTTP response reading
	// goroutine that the connection is now closed. This eliminates a race
	// where the HTTP response reading goroutine would otherwise not observe
	// the EOF until its next read, by which time a client goroutine might
	// have already tried to reuse the HTTP connection for a new request.
	// See https://golang.org/cl/76400046 and https://golang.org/issue/3514

	// 提前处理服务端发送的 close-notify 告警
	// close-notify 是一种特殊的警报消息，用于优雅地关闭 TLS 连接
	// 通过提前检查并处理close-notify警报，确保：

	// 当读取完所有应用数据且下一个记录是 close-notify 时
	// 立即返回 io.EOF 而不是 nil
	// 这样 HTTP 客户端就能正确感知连接已关闭，避免重用无效连接

	return n, nil
}

//readRecordOrCCS 从连接中读取一个或多个 TLS 记录，并更新记录层状态。一些不变条件：
// - c.in 必须已加锁
// - c.input 必须为空

// 在握手期间，以下情况中恰好会发生一种：
// - c.hand 增长
// - 调用 c.in.changeCipherSpec
// - 返回错误

func (c *Conn) readRecord() error {
	// 是否已出现过 read 错误
	if c.in.err != nil {
		return c.in.err
	}

	handshakeComplete := c.isHandshakeComplete.Load()

	// 就是 input 为空才来 readRecord 读取记录的，所以不为空一定有问题
	if c.input.Len() != 0 {
		return c.in.setErrorLocked(errors.New("tls: internal error: attempted to read record with pending application data"))
	}
	// 所谓 input 其实就是一个 []byte 包装成一个 Reader
	c.input.Reset(nil)

	// 读取 header
	// 【这里就有第一个不一样了，以前底层tcp连接是流式的，需要先读取头部获取控制信息再读取数据体】
	// 【而我们的底层是 ws 连接，不是流式的，直接读取一条二进制消息即可】
	// 改成循环读，一直读到一条 Binary 或者 Close Message 消息为止
	var msgType int
	var msg []byte
	var err error
	for {
		msgType, msg, err = c.conn.ReadMessage()
		if err != nil {
			log.Printf("读取消息失败: %v", err)
			return c.in.setErrorLocked(errors.New("read record failed"))
		}
		//【只处理 Binary 或者Close Message】
		if msgType != websocket.BinaryMessage && msgType != websocket.CloseMessage {
			continue
		} else {
			break
		}
	}

	if msgType == websocket.CloseMessage {
		c.Close()
		return c.in.setErrorLocked(errors.New("close message"))
	}

	// 走到这里说明是Binary Message
	// 先取出第一个字节作为记录类型字节
	typ := recordType(msg[0])
	// 无需存入 rawInput了，直接解密即可
	data, err := c.in.decrypt(msg[1:])
	if err != nil {
		return c.in.setErrorLocked(errors.New("decrypt failed"))
	}

	// 如果是 Application Data 消息，且没有加密算法
	// 则发送 alertUnexpectedMessage 警告
	// Application Data messages are always protected.
	if c.in.cipher == nil && typ == recordTypeApplicationData {
		return c.in.setErrorLocked(errors.New("alertUnexpectedMessage"))
	}

	// 【第四大步：根据记录类型 typ 处理不同类型的TLS记录】
	// 4.1 应用层记录，将解密后的数据 data 设置到 c.input 中拱后续读取
	// 4.2 变更密码套件记录，变更 c.in 中的密码套件
	// 4.3 握手记录，将解密后的数据 data 写入到 c.hand 中

	// 处理不同类型的TLS记录
	switch typ {
	default:
		return c.in.setErrorLocked(errors.New("alertUnexpectedMessage"))

	// 处理 TLS 应用数据记录
	case recordTypeApplicationData:
		if !handshakeComplete {
			return c.in.setErrorLocked(errors.New("alertUnexpectedMessage"))
		}
		if len(data) == 0 {
			return errors.New("empty application data record")
		}
		c.input.Reset(data)

	// 处理 TLS 握手记录
	case recordTypeHandshake:
		if len(data) == 0 {
			return errors.New("alertUnexpectedMessage")
		}
		c.hand.Write(data)
	}

	return nil
}

func (c *Conn) readHandshake(transcript transcriptHash) (any, error) {
	// 要求 hand 中至少有 4 字节数据，否则内部通过 readRecord() 读取到 hand 中
	if err := c.readHandshakeBytes(4); err != nil {
		return nil, err
	}
	data := c.hand.Bytes()

	maxHandshakeSize := maxHandshake

	n := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	if n > maxHandshakeSize {
		c.out.setErrorLocked(errors.New("alertInternalError"))
		return nil, c.in.setErrorLocked(fmt.Errorf("tls: handshake message of length %d bytes exceeds maximum of %d bytes", n, maxHandshakeSize))
	}
	if err := c.readHandshakeBytes(4 + n); err != nil {
		return nil, err
	}
	data = c.hand.Next(4 + n)
	return c.unmarshalHandshakeMessage(data, transcript)
}

func (c *Conn) unmarshalHandshakeMessage(data []byte, transcript transcriptHash) (handshakeMessage, error) {
	var m handshakeMessage
	switch data[0] {
	case typeHelloMsg:
		m = new(helloMsg)
	default:
		return nil, c.in.setErrorLocked(c.out.setErrorLocked(errors.New("alertUnexpectedMessage")))
	}

	// 因为这里的原 data 其实来自 hand 缓冲区，所以为了不破坏 hand 缓冲区
	// 进行了一次非常地道的深拷贝
	data = append([]byte(nil), data...)

	if !m.unmarshal(data) {
		return nil, c.in.setErrorLocked(c.out.setErrorLocked(errors.New("alertUnexpectedMessage")))
	}

	if transcript != nil {
		transcript.Write(data)
	}

	return m, nil
}

// readHandshakeBytes reads handshake data until c.hand contains at least n bytes.
func (c *Conn) readHandshakeBytes(n int) error {
	for c.hand.Len() < n {
		if err := c.readRecord(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Conn) Write(b []byte) (n int, err error) {
	// 通过 activeCall 检查连接是否已关闭
	for {
		x := c.activeCall.Load()
		if x&1 != 0 {
			return 0, net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x+2) {
			break
		}
	}
	defer c.activeCall.Add(-2)

	// 握手检查
	if err := c.Handshake(); err != nil {
		return 0, err
	}

	// 输出锁
	c.out.Lock()
	defer c.out.Unlock()

	if err := c.out.err; err != nil {
		return 0, err
	}

	if !c.isHandshakeComplete.Load() {
		return 0, errors.New("[Write] handshake not complete")
	}

	if c.closeNotifySent {
		return 0, errors.New("errShutdown")
	}

	n, err = c.writeRecordLocked(recordTypeApplicationData, b)
	return n, c.out.setErrorLocked(err)
}

func (c *Conn) writeHandshakeRecord(msg handshakeMessage, transcript transcriptHash) (int, error) {
	c.out.Lock()
	defer c.out.Unlock()

	data, err := msg.marshal()
	if err != nil {
		return 0, err
	}
	if transcript != nil {
		transcript.Write(data)
	}

	// 不论是写入握手消息还是应用消息，writeRecordLocked 前上 out 锁
	// writeRecordLocked 内部都会调用 out 加密
	return c.writeRecordLocked(recordTypeHandshake, data)
}

var outBufPool = sync.Pool{
	New: func() any {
		return new([]byte)
	},
}

// writeRecordLocked 写入记录，这里的 type 只能是握手或者应用了
func (c *Conn) writeRecordLocked(typ recordType, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, errors.New("zero length write")
	}

	outBufPtr := outBufPool.Get().(*[]byte)
	outBuf := *outBufPtr
	defer func() {
		// You might be tempted to simplify this by just passing &outBuf to Put,
		// but that would make the local copy of the outBuf slice header escape
		// to the heap, causing an allocation. Instead, we keep around the
		// pointer to the slice header returned by Get, which is already on the
		// heap, and overwrite and return that.
		*outBufPtr = outBuf
		outBufPool.Put(outBufPtr)
	}()

	// 注意 这里！ 因为原来是流式的所以如果数据很大可以分开写好几次
	// 但是现在是应用层的，能分开写好几次么，似乎不用管这个问题（应该内部会做处理）
	// ok 问了gemini 确实不需要！

	outBuf[0] = byte(typ)

	var err error
	outBuf, err = c.out.encrypt(outBuf, data, c.config.rand())
	if err != nil {
		return 0, err
	}
	err = c.conn.WriteMessage(websocket.BinaryMessage, outBuf)
	if err != nil {
		return 0, err
	}

	return len(data), nil
}

func (c *Conn) write(data []byte) (int, error) {
	// if c.buffering {
	// 	c.sendBuf = append(c.sendBuf, data...)
	// 	return len(data), nil
	// }
	err := c.conn.WriteMessage(websocket.BinaryMessage, data)
	if err != nil {
		return 0, err
	}
	// c.bytesSent += int64(n)
	return len(data), nil
}

func (c *Conn) Close() error {

	// 如果无需发送特殊的 close-notify 告警
	// 那么 activeCall 无用，直接关闭连接
	var x int32
	for {
		x = c.activeCall.Load()
		if x&1 != 0 {
			return net.ErrClosed
		}
		if c.activeCall.CompareAndSwap(x, x|1) {
			break
		}
	}

	if x != 0 {
		return c.conn.Close()
	}

	var alertErr error
	if c.isHandshakeComplete.Load() {
		if err := c.closeNotify(); err != nil {
			alertErr = fmt.Errorf("tls: failed to send closeNotify alert (but connection was closed anyway): %w", err)
		}
	}

	if err := c.conn.Close(); err != nil {
		return err
	}
	return alertErr
}

func (c *Conn) closeNotify() error {
	c.out.Lock()
	defer c.out.Unlock()

	if !c.closeNotifySent {
		// 5 秒超时时间
		c.SetWriteDeadline(time.Now().Add(time.Second * 5))
		// 发送 websocket.CloseMessage 关闭通知
		c.closeNotifyErr = c.conn.WriteMessage(websocket.CloseMessage, nil)

		c.closeNotifySent = true

		// 后续写入都将失败
		c.SetWriteDeadline(time.Now())
	}
	return c.closeNotifyErr
}

func (c *Conn) Handshake() error {
	return c.HandshakeContext(context.Background())
}

func (c *Conn) HandshakeContext(ctx context.Context) error {
	return c.handshakeContext(ctx)
}

func (c *Conn) handshakeContext(ctx context.Context) (ret error) {

	if c.isHandshakeComplete.Load() {
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
				_ = c.conn.Close()
				interruptRes <- handshakeCtx.Err()
			case <-done:
				interruptRes <- nil
			}
		}()
	}
	// 【第三大步：上锁与二次状态检查】
	// 上锁并二次检查握手是否已经完成
	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	if err := c.handshakeErr; err != nil {
		return err
	}
	if c.isHandshakeComplete.Load() {
		return nil
	}

	// 给 c.in 加锁，确保在握手过程中不会被其他 goroutine 访问
	// 握手过程涉及读写，加 in 锁是因为，read 和 write 上锁设计不同
	// 小 write 函数内部细粒度上锁，但是小 read 函数的不会上锁，所以都是在外部先上锁
	// 比如在这里进入握手状态机前，比如在大 Read 中上锁
	c.in.Lock()
	defer c.in.Unlock()
	// 【第四大步：执行握手】
	// 实际执行握手，返回 c.handshakeErr 握手错误
	c.handshakeErr = c.handshakeFn(handshakeCtx)
	if c.handshakeErr == nil {
		// 增加握手计数器
		c.handshakes++
	}

	// 握手没错但是标记未完成
	if c.handshakeErr == nil && !c.isHandshakeComplete.Load() {
		c.handshakeErr = errors.New("tls: internal error: handshake should have had a result")
	}
	// 握手有错但是标记完成
	if c.handshakeErr != nil && c.isHandshakeComplete.Load() {
		panic("tls: internal error: handshake returned an error but is marked successful")
	}

	return c.handshakeErr
}

func (c *Conn) handlePostHandshakeMessage() error {

	return c.handleRenegotiation()

}

// Todo: 重要，涉及重协商策略以及 isClient 问题
// 前置是需完成常规握手功能
func (c *Conn) handleRenegotiation() error {

	msg, err := c.readHandshake(nil)
	if err != nil {
		return err
	}

	helloReq, ok := msg.(*helloRequestMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(helloReq, msg)
	}

	if !c.isClient {
		return c.sendAlert(alertNoRenegotiation)
	}

	switch c.config.Renegotiation {
	case RenegotiateNever:
		return c.sendAlert(alertNoRenegotiation)
	case RenegotiateOnceAsClient:
		if c.handshakes > 1 {
			return c.sendAlert(alertNoRenegotiation)
		}
	case RenegotiateFreelyAsClient:
		// Ok.
	default:
		c.sendAlert(alertInternalError)
		return errors.New("tls: unknown Renegotiation value")
	}

	c.handshakeMutex.Lock()
	defer c.handshakeMutex.Unlock()

	c.isHandshakeComplete.Store(false)
	if c.handshakeErr = c.clientHandshake(context.Background()); c.handshakeErr == nil {
		c.handshakes++
	}
	return c.handshakeErr
}

// ===========================================================================

func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

// websocket.Conn 没有实现 SetDeadline 方法
// func (c *Conn) SetDeadline(t time.Time) error {
// 	return c.conn.SetDeadline(t)
// }

// =============================================================================

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

}

// =======================================================

func (hc *halfConn) decrypt(payload []byte) ([]byte, error) {

	// 我传进来的整个都是 payload 不是带 header 的 record
	var plaintext []byte

	// 未实现CBC模式时无需使用 paddingGood 和 paddingLen
	// paddingGood := byte(255)
	// paddingLen := 0

	explicitNonceLen := hc.explicitNonceLen()

	if hc.cipher != nil {
		switch c := hc.cipher.(type) {
		case cipher.Stream:
			c.XORKeyStream(payload, payload)
		case sm4tongsuo.AEAD:

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
		if _, isCBC := hc.cipher.(cbcMode); !isCBC && explicitNonceLen < 16 {
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
	case aead:
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
	case sm4tongsuo.AEAD:
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
