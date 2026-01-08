package e2ewebsocket

import (
	"crypto/sha1"
	"hash"

	"github.com/albert/ws_client/crypto/sm3tongsuo"
)

const localFinishedLabel = "local finished"
const remoteFinishedLabel = "remote finished"

// type finishedHash struct {
// 	local  hash.Hash
// 	remote hash.Hash
// 	prf    prfFunc
// }

// func newFinishedHash(cipherSuite *cipherSuite) finishedHash {
// 	prf, hash := prfAndHash(cipherSuite)
// 	if hash != 0 {
// 		if hash == 50 {
// 			// 因为 SM3 加入不到标准库的映射表中所以无法使用 hash.New 方法获取其哈希实现
// 			return finishedHash{sm3tongsuo.NewSM3(), sm3tongsuo.NewSM3(), prf}
// 		}
// 		return finishedHash{hash.New(), hash.New(), prf}
// 	}
// 	return finishedHash{sha1.New(), sha1.New(), prf}
// }

// func (h *finishedHash) Write(msg []byte) (n int, err error) {
// 	h.local.Write(msg)
// 	h.remote.Write(msg)
// 	return len(msg), nil
// }

// // func (h *finishedHash) discardHandshakeBuffer() {
// // 	h.buffer = nil
// // }

// func (h finishedHash) Sum() []byte {
// 	return h.local.Sum(nil)
// }

// func (h finishedHash) localSum(masterSecret []byte) []byte {
// 	return h.prf(masterSecret, localFinishedLabel, h.Sum(), finishedVerifyLength)
// }

// func (h finishedHash) remoteSum(masterSecret []byte) []byte {
// 	return h.prf(masterSecret, remoteFinishedLabel, h.Sum(), finishedVerifyLength)
// }

type finishedHash struct {
	localFinishedLabel  string
	remoteFinishedLabel string

	coreHash hash.Hash
	prf      prfFunc
}

func newFinishedHash(cipherSuite *cipherSuite, localFinishedLabel string, remoteFinishedLabel string) finishedHash {
	prf, hash := prfAndHash(cipherSuite)
	if hash != 0 {
		if hash == 50 {
			// 因为 SM3 加入不到标准库的映射表中所以无法使用 hash.New 方法获取其哈希实现
			return finishedHash{localFinishedLabel, remoteFinishedLabel, sm3tongsuo.NewSM3(), prf}
		}
		return finishedHash{localFinishedLabel, remoteFinishedLabel, hash.New(), prf}
	}
	return finishedHash{localFinishedLabel, remoteFinishedLabel, sha1.New(), prf}
}

func (h *finishedHash) Write(msg []byte) (n int, err error) {
	h.coreHash.Write(msg)
	return len(msg), nil
}

func (h finishedHash) Sum() []byte {
	return h.coreHash.Sum(nil)
}

// 但是这个 prfSum 确实不一样，因为label不一样，这个后续考虑用用户id 做 label
func (h finishedHash) localSum(masterSecret []byte) []byte {
	return h.prf(masterSecret, h.localFinishedLabel, h.Sum(), finishedVerifyLength)
}

func (h finishedHash) remoteSum(masterSecret []byte) []byte {
	return h.prf(masterSecret, h.remoteFinishedLabel, h.Sum(), finishedVerifyLength)
}
