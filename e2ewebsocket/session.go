package e2ewebsocket

import (
	"context"
	"hash"
	"sync"
	"sync/atomic"
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

	hand [][]byte

	handshakeChan chan sessionMsg
}

func NewSession(id SessionID, remoteId string, conn *Conn) *Session {
	s := Session{
		id:            id,
		remoteId:      remoteId,
		conn:          conn,
		handshakeChan: make(chan sessionMsg, 16),
	}
	s.in.cond = sync.NewCond(&s.in)
	s.out.cond = sync.NewCond(&s.out)
	s.handshakeFn = s.symHandshake
	return &s
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
	// ########### cond 很重要，对称握手特有的竞态问题
	cond       *sync.Cond
}


func (hc *halfConn) decrypt(payload []byte) ([]byte, error) {
	hc.Lock()
	defer hc.Unlock()

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