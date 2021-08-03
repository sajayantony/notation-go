package jws

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"

	"github.com/golang-jwt/jwt"
)

// SigningMethodFromKey picks up recommended algorithm for keys
func SigningMethodFromKey(key interface{}) (jwt.SigningMethod, error) {
	if k, ok := key.(interface {
		Public() crypto.PublicKey
	}); ok {
		key = k.Public()
	}

	switch key := key.(type) {
	case *rsa.PublicKey:
		switch key.Size() {
		case 256:
			return jwt.SigningMethodRS256, nil
		case 384:
			return jwt.SigningMethodRS384, nil
		case 512:
			return jwt.SigningMethodRS512, nil
		default:
			return jwt.SigningMethodRS256, nil
		}
	case *ecdsa.PublicKey: // Reference: https://datatracker.ietf.org/doc/html/rfc7518#section-3.1
		switch key.Curve.Params().BitSize {
		case jwt.SigningMethodES256.CurveBits:
			return jwt.SigningMethodES256, nil
		case jwt.SigningMethodES384.CurveBits:
			return jwt.SigningMethodES384, nil
		case jwt.SigningMethodES512.CurveBits:
			return jwt.SigningMethodES512, nil
		default:
			return nil, errors.New("ecdsa key not recognized")
		}
	case *ed25519.PublicKey:
		return jwt.SigningMethodEdDSA, nil
	}
	return nil, errors.New("key not recognized")
}
