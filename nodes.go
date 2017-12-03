package mls

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

var (
	// Parameters for Merkle tree
	emptyNodeValue = []byte{0x00}
	leafHashPrefix = []byte{0x01}
	pairHashPrefix = []byte{0x02}

	// Parameters for ECDH
	ecdhCurve = elliptic.P256()
)

func emptyMerkleLeaf() []byte {
	h := sha256.New()
	h.Write(emptyNodeValue)
	return h.Sum(nil)
}

func merkleLeaf(value []byte) []byte {
	h := sha256.New()
	h.Write(leafHashPrefix)
	h.Write(value)
	return h.Sum(nil)
}

func merklePairHash(lhs, rhs []byte) []byte {
	h := sha256.New()
	h.Write(pairHashPrefix)
	h.Write(lhs)
	h.Write(rhs)
	return h.Sum(nil)
}

var merkleNodeDefn = &nodeDefinition{
	valid: func(x Node) bool {
		_, ok := x.([]byte)
		return ok
	},

	equal: func(x, y Node) bool {
		xb, okx := x.([]byte)
		yb, oky := y.([]byte)
		return okx && oky && bytes.Equal(xb, yb)
	},

	create: func(data []byte) Node {
		return data
	},

	combine: func(x, y Node) ([]byte, error) {
		xb, okx := x.([]byte)
		yb, oky := y.([]byte)
		if !okx || !oky {
			return nil, InvalidNodeError
		}

		return merklePairHash(xb, yb), nil
	},
}

type ecdhPublicKey struct {
	x, y *big.Int
}

type ecdhKey struct {
	data      []byte
	d         []byte
	publicKey *ecdhPublicKey
}

func newECDHKey() *ecdhKey {
	d, x, y, _ := elliptic.GenerateKey(ecdhCurve, rand.Reader)
	return &ecdhKey{d: d, publicKey: &ecdhPublicKey{x: x, y: y}}
}

func (k ecdhKey) derive(pub *ecdhPublicKey) []byte {
	zz, _ := ecdhCurve.ScalarMult(pub.x, pub.y, k.d)

	h := sha256.New()
	h.Write(zz.Bytes())
	return h.Sum(nil)
}

func ecdhKeyFromData(data []byte) *ecdhKey {
	h := sha256.New()
	h.Write(data)
	d := h.Sum(nil)
	x, y := ecdhCurve.ScalarBaseMult(d)
	return &ecdhKey{data: data, d: d, publicKey: &ecdhPublicKey{x: x, y: y}}
}

func ecdhKeyFromPrivateKey(d []byte) *ecdhKey {
	x, y := ecdhCurve.ScalarBaseMult(d)
	return &ecdhKey{d: d, publicKey: &ecdhPublicKey{x: x, y: y}}
}

func ecdhKeyFromPublicKey(x, y *big.Int) *ecdhKey {
	return &ecdhKey{publicKey: &ecdhPublicKey{x: x, y: y}}
}

var ecdhNodeDefn = &nodeDefinition{
	valid: func(x Node) bool {
		xk, ok := x.(*ecdhKey)
		if !ok {
			return false
		}

		// Must have a public key
		return xk.publicKey != nil && xk.publicKey != nil
	},

	equal: func(x, y Node) bool {
		xk, okx := x.(*ecdhKey)
		yk, oky := y.(*ecdhKey)
		return okx && oky &&
			xk.publicKey.x.Cmp(yk.publicKey.x) == 0 &&
			xk.publicKey.y.Cmp(yk.publicKey.y) == 0
	},

	create: func(data []byte) Node {
		return ecdhKeyFromData(data)
	},

	combine: func(x, y Node) ([]byte, error) {
		xk, okx := x.(*ecdhKey)
		yk, oky := y.(*ecdhKey)
		if !okx || !oky {
			return nil, InvalidNodeError
		}

		switch {
		case xk.d != nil && yk.publicKey != nil:
			return xk.derive(yk.publicKey), nil
		case yk.d != nil && xk.publicKey != nil:
			return xk.derive(yk.publicKey), nil
		default:
			return nil, IncompatibleNodesError
		}
	},
}
