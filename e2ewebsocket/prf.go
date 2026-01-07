package e2ewebsocket

import (
	"crypto"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"

	"github.com/albert/ws_client/crypto/sm3tongsuo"
)

const masterSecretLength = 48
const finishedVerifyLength = 12

const masterSecretLabel = "master secret"
const keyExpansionLabel = "key expansion"

func masterFromPreMasterSecret(version uint16, suite *cipherSuite, preMasterSecret, clientRandom, serverRandom []byte) []byte {
	seed := make([]byte, 0, len(clientRandom)+len(serverRandom))
	seed = append(seed, clientRandom...)
	seed = append(seed, serverRandom...)

	return prf(suite)(preMasterSecret, masterSecretLabel, seed, masterSecretLength)
}

func keysFromMasterSecret(version uint16, suite *cipherSuite, masterSecret, clientRandom, serverRandom []byte, macLen, keyLen, ivLen int) (clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV []byte) {
	seed := make([]byte, 0, len(serverRandom)+len(clientRandom))
	seed = append(seed, serverRandom...)
	seed = append(seed, clientRandom...)

	n := 2*macLen + 2*keyLen + 2*ivLen
	keyMaterial := prf(suite)(masterSecret, keyExpansionLabel, seed, n)
	clientMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	serverMAC = keyMaterial[:macLen]
	keyMaterial = keyMaterial[macLen:]
	clientKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	serverKey = keyMaterial[:keyLen]
	keyMaterial = keyMaterial[keyLen:]
	clientIV = keyMaterial[:ivLen]
	keyMaterial = keyMaterial[ivLen:]
	serverIV = keyMaterial[:ivLen]
	return
}

func prf(suite *cipherSuite) prfFunc {
	prf, _ := prfAndHash(suite)
	return prf
}

func prfAndHash(suite *cipherSuite) (prfFunc, crypto.Hash) {

	if suite.flags&suiteSHA384 != 0 {
		return prfFromHash(sha512.New384), crypto.SHA384
	}
	// 新增
	if suite.flags&suiteSM3 != 0 {
		return prfFromHash(sm3tongsuo.NewSM3), sm3tongsuo.SM3HASH
	}
	return prfFromHash(sha256.New), crypto.SHA256

}

type prfFunc func(secret []byte, label string, seed []byte, keyLen int) []byte

func prfFromHash(hashFunc func() hash.Hash) prfFunc {
	return func(secret []byte, label string, seed []byte, keyLen int) []byte {
		return PRF(hashFunc, secret, label, seed, keyLen)
	}
}

func PRF(hash func() hash.Hash, secret []byte, label string, seed []byte, keyLen int) []byte {
	labelAndSeed := make([]byte, len(label)+len(seed))
	copy(labelAndSeed, label)
	copy(labelAndSeed[len(label):], seed)

	result := make([]byte, keyLen)
	pHash(hash, result, secret, labelAndSeed)
	return result
}

func pHash(hash func() hash.Hash, result, secret, seed []byte) {
	h := hmac.New(hash, secret)
	h.Write(seed)
	a := h.Sum(nil)

	for len(result) > 0 {
		h.Reset()
		h.Write(a)
		h.Write(seed)
		b := h.Sum(nil)
		n := copy(result, b)
		result = result[n:]

		h.Reset()
		h.Write(a)
		a = h.Sum(nil)
	}
}
