package util

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/5dao/hd/util/secp256k1"
)

// ECDAOfSecp256k1 ECDAOfSecp256k1
func ECDAOfSecp256k1(key []byte) (*ecdsa.PrivateKey, ecdsa.PublicKey) {
	curve := secp256k1.S256()

	x, y := curve.ScalarBaseMult(key)

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(key),
	}
	return priv, priv.PublicKey
}
