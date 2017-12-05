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

type MerkleFrontierEntry struct {
	Value []byte
	Size  uint
}

type MerkleFrontier []MerkleFrontierEntry

func NewMerkleFrontier(f *Frontier) (MerkleFrontier, error) {
	mf := make(MerkleFrontier, len(f.Entries))
	for i, e := range f.Entries {
		if !merkleNodeDefn.valid(e.Value) {
			return nil, InvalidNodeError
		}

		mf[i] = MerkleFrontierEntry{
			Value: e.Value.([]byte),
			Size:  e.Size,
		}
	}

	return mf, nil
}

func (mf MerkleFrontier) Frontier() *Frontier {
	f := &Frontier{
		defn:    merkleNodeDefn,
		Entries: make([]FrontierEntry, len(mf)),
	}

	for i, e := range mf {
		f.Entries[i] = FrontierEntry{
			Value: e.Value,
			Size:  e.Size,
		}
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

	err = tree.Build()
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
		return err
	}

	x, y := elliptic.Unmarshal(ecdhCurve, pt)
	if x == nil {
		return fmt.Errorf("Improperly formatted elliptic curve point")
	}

	k.PrivateKey.PublicKey = ecdsa.PublicKey{Curve: ecdhCurve, X: x, Y: y}
	return nil
}

func (k *ECKey) PublicKey() *ECKey {
	return ECKeyFromPublicKey(&k.PrivateKey.PublicKey)
}

func (k ECKey) bytes() []byte {
	x := k.PrivateKey.PublicKey.X
	y := k.PrivateKey.PublicKey.Y
	return elliptic.Marshal(ecdhCurve, x, y)
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

func (k ECKey) sign(message []byte) ([]byte, error) {
	if k.PrivateKey.D == nil {
		return nil, fmt.Errorf("Cannot sign without private key")
	}

	h := sha256.New()
	h.Write(message)
	r, s, err := ecdsa.Sign(rand.Reader, &k.PrivateKey, h.Sum(nil))
	if err != nil {
		return nil, err
	}

	// XXX Ad-hoc signature encoding, because padding is hard
	signature := []byte{byte(len(r.Bytes()))}
	signature = append(signature, r.Bytes()...)
	signature = append(signature, s.Bytes()...)
	return signature, nil
}

func (k ECKey) verify(message, signature []byte) bool {
	// XXX Should be more defensive here
	cut := int(signature[0])
	r := big.NewInt(0).SetBytes(signature[1 : cut+1])
	s := big.NewInt(0).SetBytes(signature[cut+1:])

	pub := &k.PrivateKey.PublicKey
	h := sha256.New()
	h.Write(message)
	return ecdsa.Verify(pub, h.Sum(nil), r, s)
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

type ECFrontierEntry struct {
	Value *ECKey
	Size  uint
}

type ECFrontier []ECFrontierEntry

func NewECFrontier(f *Frontier) (ECFrontier, error) {
	mf := make(ECFrontier, len(f.Entries))
	for i, e := range f.Entries {
		if !ecdhNodeDefn.valid(e.Value) {
			return nil, InvalidNodeError
		}

		mf[i] = ECFrontierEntry{
			Value: e.Value.(*ECKey),
			Size:  e.Size,
		}
	}

	return mf, nil
}

func (mf ECFrontier) Frontier() *Frontier {
	f := &Frontier{
		defn:    ecdhNodeDefn,
		Entries: make([]FrontierEntry, len(mf)),
	}

	for i, e := range mf {
		f.Entries[i] = FrontierEntry{
			Value: e.Value,
			Size:  e.Size,
		}
	}

	return f
}
