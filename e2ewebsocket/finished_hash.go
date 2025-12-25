package e2ewebsocket

import (
	"crypto/md5"
	"crypto/sha1"
	"hash"
)

const localFinishedLabel = "local finished"
const remoteFinishedLabel = "remote finished"

func newFinishedHash(cipherSuite *cipherSuite) finishedHash {
	var buffer []byte
	prf, hash := prfAndHash(cipherSuite)
	if hash != 0 {
		return finishedHash{hash.New(), hash.New(), nil, nil, buffer, prf}
	}

	return finishedHash{sha1.New(), sha1.New(), md5.New(), md5.New(), buffer, prf}
}

// A finishedHash calculates the hash of a set of handshake messages suitable
// for including in a Finished message.
type finishedHash struct {
	client hash.Hash
	server hash.Hash

	// In TLS 1.2, a full buffer is sadly required.
	buffer []byte

	// version uint16

	prf prfFunc
}

func (h *finishedHash) Write(msg []byte) (n int, err error) {
	h.client.Write(msg)
	h.server.Write(msg)

	if h.buffer != nil {
		h.buffer = append(h.buffer, msg...)
	}

	return len(msg), nil
}

func (h *finishedHash) discardHandshakeBuffer() {
	h.buffer = nil
}

func (h finishedHash) Sum() []byte {
	return h.client.Sum(nil)
}

func (h finishedHash) localSum(masterSecret []byte) []byte {
	return h.prf(masterSecret, localFinishedLabel, h.Sum(), finishedVerifyLength)
}

func (h finishedHash) remoteSum(masterSecret []byte) []byte {
	return h.prf(masterSecret, remoteFinishedLabel, h.Sum(), finishedVerifyLength)
}
