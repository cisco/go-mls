package mls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
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

type ECKey struct {
	data []byte
	ecdsa.PrivateKey
}

func (k ECKey) MarshalJSON() ([]byte, error) {
	pub := k.PrivateKey.PublicKey
	pt := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	return json.Marshal(pt)
}

func (k *ECKey) UnmarshalJSON(data []byte) error {
	var pt []byte
	err := json.Unmarshal(data, &pt)
	if err != nil {
		panic("AAAAHHHH" + err.Error())
		return err
	}

	x, y := elliptic.Unmarshal(ecdhCurve, pt)
	if x == nil {
		return fmt.Errorf("Improperly formatted elliptic curve point")
	}

	k.PrivateKey.PublicKey = ecdsa.PublicKey{Curve: ecdhCurve, X: x, Y: y}
	return nil
}

func (k ECKey) derive(other *ECKey) []byte {
	d := k.PrivateKey.D.Bytes()
	x := other.PrivateKey.PublicKey.X
	y := other.PrivateKey.PublicKey.Y
	zz, _ := ecdhCurve.ScalarMult(x, y, d)

	h := sha256.New()
	h.Write(zz.Bytes())
	return h.Sum(nil)
}

func NewECKey() *ECKey {
	priv, _ := ecdsa.GenerateKey(ecdhCurve, rand.Reader)
	return &ECKey{PrivateKey: *priv}
}

func ECKeyFromData(data []byte) *ECKey {
	h := sha256.New()
	h.Write(data)
	db := h.Sum(nil)
	x, y := ecdhCurve.ScalarBaseMult(db)

	d := big.NewInt(0).SetBytes(db)
	return &ECKey{
		data: data,
		PrivateKey: ecdsa.PrivateKey{
			D:         d,
			PublicKey: ecdsa.PublicKey{Curve: ecdhCurve, X: x, Y: y},
		},
	}
}

func ECKeyFromPrivateKey(priv *ecdsa.PrivateKey) *ECKey {
	return &ECKey{PrivateKey: *priv}
}

func ECKeyFromPublicKey(pub *ecdsa.PublicKey) *ECKey {
	return &ECKey{PrivateKey: ecdsa.PrivateKey{PublicKey: *pub}}
}

var ecdhNodeDefn = &nodeDefinition{
	valid: func(x Node) bool {
		xk, ok := x.(*ECKey)
		if !ok {
			return false
		}

		// Must have a public key
		return xk.PrivateKey.PublicKey.X != nil &&
			xk.PrivateKey.PublicKey.Y != nil
	},

	equal: func(x, y Node) bool {
		xk, okx := x.(*ECKey)
		yk, oky := y.(*ECKey)
		return okx && oky &&
			xk.PrivateKey.PublicKey.X.Cmp(yk.PrivateKey.PublicKey.X) == 0 &&
			xk.PrivateKey.PublicKey.Y.Cmp(yk.PrivateKey.PublicKey.Y) == 0
	},

	create: func(data []byte) Node {
		return ECKeyFromData(data)
	},

	combine: func(x, y Node) ([]byte, error) {
		xk, okx := x.(*ECKey)
		yk, oky := y.(*ECKey)
		if !okx || !oky {
			return nil, InvalidNodeError
		}

		switch {
		case xk.PrivateKey.D != nil:
			return xk.derive(yk), nil
		case yk.PrivateKey.D != nil:
			return yk.derive(xk), nil
		default:
			return nil, IncompatibleNodesError
		}
	},
}
