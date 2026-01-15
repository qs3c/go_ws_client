package e2ewebsocket

import (
	"context"
	"hash"
	"sync"
	"sync/atomic"
)

// Session: 负责单个逻辑会话的协商和加密
type Session struct {
	id                  string
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
