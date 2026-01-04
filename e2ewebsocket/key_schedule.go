package e2ewebsocket

import (
	"crypto/ecdh"
	"errors"
	"io"

	"github.com/albert/ws_client/crypto/ecdh_curve"
)

func generateECDHEKey(rand io.Reader, curveID CurveID) (ecdh_curve.PrivateKey, error) {
	curve, ok := curveForCurveID(curveID)
	if !ok {
		return nil, errors.New("tls: internal error: unsupported curve")
	}

	return curve.GenerateKey(rand)
}

func curveForCurveID(id CurveID) (ecdh_curve.Curve, bool) {
	// todo：这里如果是 sm2 的curve 要特殊构造【主要是双方的id，己方的静态私钥和对方的静态公钥】

	switch id {
	case X25519:
		return trans(ecdh.X25519()), true
	case CurveP256:
		return trans(ecdh.P256()), true
	case CurveP384:
		return trans(ecdh.P384()), true
	case CurveP521:
		return trans(ecdh.P521()), true
	default:
		return nil, false
	}
}

func trans(curve ecdh.Curve) ecdh_curve.Curve {
	return curve.(ecdh_curve.Curve)
}
