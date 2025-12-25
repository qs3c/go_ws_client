package e2ewebsocket

import (
	"crypto"
	"crypto/internal/fips140/tls12"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
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
		return prf12(sha512.New384), crypto.SHA384
	}
	return prf12(sha256.New), crypto.SHA256

}

type prfFunc func(secret []byte, label string, seed []byte, keyLen int) []byte

func prf12(hashFunc func() hash.Hash) prfFunc {
	return func(secret []byte, label string, seed []byte, keyLen int) []byte {
		return tls12.PRF(hashFunc, secret, label, seed, keyLen)
	}
}
