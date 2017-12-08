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

///
/// Merkle Tree
///

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

	publicEqual: func(x, y Node) bool {
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

type MerkleFrontier [][]byte

func NewMerkleFrontier(f []Node) (MerkleFrontier, error) {
	mf := make(MerkleFrontier, len(f))
	for i, e := range f {
		if !merkleNodeDefn.valid(e) {
			return nil, InvalidNodeError
		}

		mf[i] = e.([]byte)
	}

	return mf, nil
}

func (mf MerkleFrontier) Nodes() []Node {
	f := make([]Node, len(mf))
	for i, e := range mf {
		f[i] = e
	}
	return f
}

type MerkleCopath struct {
	Index uint
	Size  uint
	Nodes [][]byte
}

func NewMerkleCopath(c *Copath) (*MerkleCopath, error) {
	mc := &MerkleCopath{
		Index: c.Index,
		Size:  c.Size,
		Nodes: make([][]byte, len(c.Nodes)),
	}

	for i, n := range c.Nodes {
		if !merkleNodeDefn.valid(n) {
			return nil, InvalidNodeError
		}
		mc.Nodes[i] = n.([]byte)
	}

	return mc, nil
}

func (mc MerkleCopath) Copath() *Copath {
	c := &Copath{
		defn:  merkleNodeDefn,
		Index: mc.Index,
		Size:  mc.Size,
		Nodes: make([]Node, len(mc.Nodes)),
	}

	for i, e := range mc.Nodes {
		c.Nodes[i] = e
	}

	return c
}

func (mc MerkleCopath) Root(leaf []byte) ([]byte, error) {
	tree, err := newTreeFromCopath(mc.Copath())
	if err != nil {
		return nil, err
	}

	tree.nodes[2*mc.Index] = leaf

	err = tree.Build([]uint{2 * mc.Index})
	if err != nil {
		return nil, err
	}

	root, err := tree.Root()
	if err != nil {
		return nil, err
	}

	return root.([]byte), nil
}

///
/// ECDH Tree
///

type ECNode struct {
	Data       []byte
	PrivateKey ECPrivateKey
}

type ECPrivateKey struct {
	D         *big.Int
	PublicKey ECPublicKey
}

type ECPublicKey struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

func (k ECPublicKey) bytes() []byte {
	return elliptic.Marshal(ecdhCurve, k.X, k.Y)
}

func (k ECPublicKey) Equal(other ECPublicKey) bool {
	return bytes.Equal(k.bytes(), other.bytes())
}

func (pub ECPublicKey) MarshalJSON() ([]byte, error) {
	pt := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	return json.Marshal(pt)
}

func (pub *ECPublicKey) UnmarshalJSON(data []byte) error {
	var pt []byte
	err := json.Unmarshal(data, &pt)
	if err != nil {
		return err
	}

	x, y := elliptic.Unmarshal(ecdhCurve, pt)
	if x == nil {
		return fmt.Errorf("Improperly formatted elliptic curve point")
	}

	pub.Curve, pub.X, pub.Y = ecdhCurve, x, y
	return nil
}

func (k ECPrivateKey) derive(other ECPublicKey) []byte {
	zz, _ := ecdhCurve.ScalarMult(other.X, other.Y, k.D.Bytes())

	// TODO Use a real KDF
	h := sha256.New()
	h.Write(zz.Bytes())
	return h.Sum(nil)
}

func (k ECPrivateKey) sign(message []byte) ([]byte, error) {
	if k.D == nil {
		return nil, fmt.Errorf("Cannot sign without private key")
	}

	h := sha256.New()
	h.Write(message)
	priv := &ecdsa.PrivateKey{
		D: k.D,
		PublicKey: ecdsa.PublicKey{
			Curve: k.PublicKey.Curve,
			X:     k.PublicKey.X,
			Y:     k.PublicKey.Y,
		},
	}
	r, s, err := ecdsa.Sign(rand.Reader, priv, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	// XXX Ad-hoc signature encoding, because padding is hard
	signature := []byte{byte(len(r.Bytes()))}
	signature = append(signature, r.Bytes()...)
	signature = append(signature, s.Bytes()...)
	return signature, nil
}

func (k ECPublicKey) verify(message, signature []byte) bool {
	// XXX Should be more defensive here
	cut := int(signature[0])
	r := big.NewInt(0).SetBytes(signature[1 : cut+1])
	s := big.NewInt(0).SetBytes(signature[cut+1:])

	pub := &ecdsa.PublicKey{Curve: k.Curve, X: k.X, Y: k.Y}
	h := sha256.New()
	h.Write(message)
	return ecdsa.Verify(pub, h.Sum(nil), r, s)
}

func NewECPrivateKey() ECPrivateKey {
	priv, _ := ecdsa.GenerateKey(ecdhCurve, rand.Reader)
	return ECPrivateKey{
		D: priv.D,
		PublicKey: ECPublicKey{
			Curve: priv.PublicKey.Curve,
			X:     priv.PublicKey.X,
			Y:     priv.PublicKey.Y,
		},
	}
}

func ECNodeFromData(data []byte) *ECNode {
	h := sha256.New()
	h.Write(data)
	db := h.Sum(nil)
	x, y := ecdhCurve.ScalarBaseMult(db)

	d := big.NewInt(0).SetBytes(db)
	return &ECNode{
		Data: data,
		PrivateKey: ECPrivateKey{
			D:         d,
			PublicKey: ECPublicKey{Curve: ecdhCurve, X: x, Y: y},
		},
	}
}

func ECNodeFromPrivateKey(priv ECPrivateKey) *ECNode {
	return &ECNode{PrivateKey: priv}
}

func ECNodeFromPublicKey(pub ECPublicKey) *ECNode {
	return &ECNode{PrivateKey: ECPrivateKey{PublicKey: pub}}
}

var ecdhNodeDefn = &nodeDefinition{
	valid: func(x Node) bool {
		xk, ok := x.(*ECNode)
		if !ok {
			return false
		}

		// Must have a public key
		return xk.PrivateKey.PublicKey.X != nil &&
			xk.PrivateKey.PublicKey.Y != nil
	},

	equal: func(x, y Node) bool {
		xk, okx := x.(*ECNode)
		yk, oky := y.(*ECNode)
		if !okx || !oky {
			return false
		}

		// Either both D values are nil or they have equal values
		xd := xk.PrivateKey.D
		yd := yk.PrivateKey.D
		xdn := (xk.PrivateKey.D == nil)
		ydn := (yk.PrivateKey.D == nil)
		deq := ((xdn && ydn) || (!xdn && !ydn && xd.Cmp(yd) == 0))
		if !deq {
			return false
		}

		xb := xk.PrivateKey.PublicKey.bytes()
		yb := yk.PrivateKey.PublicKey.bytes()
		return bytes.Equal(xb, yb)
	},

	publicEqual: func(x, y Node) bool {
		xk, okx := x.(*ECNode)
		yk, oky := y.(*ECNode)
		return okx && oky && xk.PrivateKey.PublicKey.Equal(yk.PrivateKey.PublicKey)
	},

	create: func(data []byte) Node {
		return ECNodeFromData(data)
	},

	combine: func(x, y Node) ([]byte, error) {
		xk, okx := x.(*ECNode)
		yk, oky := y.(*ECNode)
		if !okx || !oky {
			return nil, InvalidNodeError
		}

		switch {
		case xk.PrivateKey.D != nil:
			return xk.PrivateKey.derive(yk.PrivateKey.PublicKey), nil
		case yk.PrivateKey.D != nil:
			return yk.PrivateKey.derive(xk.PrivateKey.PublicKey), nil
		default:
			return nil, IncompatibleNodesError
		}
	},
}

type ECFrontier []ECPublicKey

func NewECFrontier(f []Node) (ECFrontier, error) {
	ecf := make(ECFrontier, len(f))
	for i, e := range f {
		if !ecdhNodeDefn.valid(e) {
			return nil, InvalidNodeError
		}

		ecf[i] = e.(*ECNode).PrivateKey.PublicKey
	}

	return ecf, nil
}

func (ecf ECFrontier) Nodes() []Node {
	f := make([]Node, len(ecf))
	for i, e := range ecf {
		f[i] = ECNodeFromPublicKey(e)
	}

	return f
}
