package mls

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"github.com/bifurcation/mint/syntax"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
)

///
/// Merkle Tree
///

var (
	blankNodeValue = []byte{0x00}
	leafHashPrefix = []byte{0x01}
	pairHashPrefix = []byte{0x02}
)

// opaque MerkleNode<1..2^8-1>;
type MerkleNode struct {
	Value []byte `tls:"min=1,head=1"`
}

func NewMerkleNode(obj interface{}) MerkleNode {
	data, err := syntax.Marshal(obj)
	if err != nil {
		panic(err)
	}

	return MerkleNode{merkleLeaf(data)}
}

func BlankMerkleNode() MerkleNode {
	return MerkleNode{blankNodeValue}
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

func (mn MerkleNode) isBlank() bool {
	return bytes.Equal(mn.Value, blankNodeValue)
}

var merkleNodeDefn = &nodeDefinition{
	valid: func(x Node) bool {
		_, ok := x.(MerkleNode)
		return ok
	},

	equal: func(x, y Node) bool {
		xn, okx := x.(MerkleNode)
		yn, oky := y.(MerkleNode)
		return okx && oky && bytes.Equal(xn.Value, yn.Value)
	},

	publicEqual: func(x, y Node) bool {
		xn, okx := x.(MerkleNode)
		yn, oky := y.(MerkleNode)
		return okx && oky && bytes.Equal(xn.Value, yn.Value)
	},

	combine: func(x, y Node) (Node, error) {
		xn, okx := x.(MerkleNode)
		yn, oky := y.(MerkleNode)
		if !okx || !oky {
			return nil, InvalidNodeError
		}

		if xn.isBlank() {
			return yn, nil
		} else if yn.isBlank() {
			return xn, nil
		}

		return MerkleNode{Value: merklePairHash(xn.Value, yn.Value)}, nil
	},
}

// MerklePath is used mainly for converting to/from []Node for marshal/unmarshal
type MerklePath []MerkleNode

func NewMerklePath(f []Node) (MerklePath, error) {
	mp := make(MerklePath, len(f))
	for i, e := range f {
		if !merkleNodeDefn.valid(e) {
			return nil, InvalidNodeError
		}

		mp[i] = e.(MerkleNode)
	}

	return mp, nil
}

func (mp MerklePath) Nodes() []Node {
	f := make([]Node, len(mp))
	for i, e := range mp {
		f[i] = e
	}
	return f
}

func (mp MerklePath) RootAsFrontier() ([]byte, error) {
	// The size only matters because its frontier has the same number of nodes as mp
	size := uint(1<<uint(len(mp))) - 1
	tree, err := newTreeFromFrontier(merkleNodeDefn, size, mp.Nodes())
	if err != nil {
		return nil, err
	}

	root, err := tree.Root()
	if err != nil {
		return nil, err
	}

	return root.(MerkleNode).Value, nil
}

// Interpret the path as a copath and compute the root
func (mp MerklePath) RootAsCopath(index, size uint, leaf MerkleNode) ([]byte, error) {
	tree, err := newTreeFromCopath(merkleNodeDefn, index, size, mp.Nodes())
	if err != nil {
		return nil, err
	}

	err = tree.Update(index, leaf)
	if err != nil {
		return nil, err
	}

	root, err := tree.Root()
	if err != nil {
		return nil, err
	}

	return root.(MerkleNode).Value, nil
}

///
/// ECDH Tree
///

type DHPrivateKey struct {
	priv      [32]byte
	PublicKey DHPublicKey
}

func NewDHPrivateKey() DHPrivateKey {
	priv := DHPrivateKey{}
	rand.Read(priv.priv[:])
	curve25519.ScalarBaseMult(&priv.PublicKey.pub, &priv.priv)
	return priv
}

func (priv DHPrivateKey) derive(other DHPublicKey) []byte {
	out := [32]byte{}
	curve25519.ScalarMult(&out, &priv.priv, &other.pub)
	return out[:]
}

type DHPublicKey struct {
	pub [32]byte
}

// opaque DHPublicKey<1..2^16-1>;
type rawECPublicKey struct {
	Value []byte `tls:"head=2,min=1"`
}

func (pub DHPublicKey) Equal(other DHPublicKey) bool {
	return pub == other
}

func (pub DHPublicKey) MarshalTLS() ([]byte, error) {
	return syntax.Marshal(rawECPublicKey{pub.pub[:]})
}

func (pub *DHPublicKey) UnmarshalTLS(data []byte) (int, error) {
	var raw rawECPublicKey
	n, err := syntax.Unmarshal(data, &raw)
	if err != nil {
		return 0, err
	}

	if len(raw.Value) != 32 {
		return 0, fmt.Errorf("DH key has incorrect length %d != 32", len(raw.Value))
	}

	copy(pub.pub[:], raw.Value)
	return n, nil
}

type SignaturePrivateKey struct {
	priv      ed25519.PrivateKey
	PublicKey SignaturePublicKey
}

func NewSignaturePrivateKey() SignaturePrivateKey {
	// XXX: Ignoring error
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return SignaturePrivateKey{
		priv:      priv,
		PublicKey: SignaturePublicKey{pub: pub},
	}
}

func (priv SignaturePrivateKey) sign(message []byte) []byte {
	return ed25519.Sign(priv.priv, message)
}

// opaque SignaturePublicKey<1..2^16-1>;
type SignaturePublicKey struct {
	pub ed25519.PublicKey `tls:"head=2"`
}

func (pub SignaturePublicKey) MarshalTLS() ([]byte, error) {
	return syntax.Marshal(rawECPublicKey{pub.pub})
}

func (pub *SignaturePublicKey) UnmarshalTLS(data []byte) (int, error) {
	var raw rawECPublicKey
	n, err := syntax.Unmarshal(data, &raw)
	if err != nil {
		return 0, err
	}

	pub.pub = raw.Value
	return n, nil
}

func (pub SignaturePublicKey) verify(message []byte, signature []byte) bool {
	return ed25519.Verify(pub.pub, message, signature)
}

func (pub SignaturePublicKey) Equal(other SignaturePublicKey) bool {
	return bytes.Equal(pub.pub, other.pub)
}

type DHNode struct {
	isBlank    bool
	hasPrivate bool
	Data       []byte
	PrivateKey DHPrivateKey
}

func BlankDHNode() *DHNode {
	return &DHNode{isBlank: true}
}

func DHNodeFromData(data []byte) *DHNode {
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)

	var priv, pub [32]byte
	copy(priv[:], digest)
	curve25519.ScalarBaseMult(&pub, &priv)

	return &DHNode{
		hasPrivate: true,
		Data:       data,
		PrivateKey: DHPrivateKey{
			priv:      priv,
			PublicKey: DHPublicKey{pub},
		},
	}
}

func DHNodeFromPrivateKey(priv DHPrivateKey) *DHNode {
	return &DHNode{
		hasPrivate: true,
		PrivateKey: priv,
	}
}

func DHNodeFromPublicKey(pub DHPublicKey) *DHNode {
	return &DHNode{
		hasPrivate: false,
		PrivateKey: DHPrivateKey{PublicKey: pub},
	}
}

var dhNodeDefn = &nodeDefinition{
	valid: func(x Node) bool {
		_, ok := x.(*DHNode)
		return ok
	},

	equal: func(x, y Node) bool {
		xk, okx := x.(*DHNode)
		yk, oky := y.(*DHNode)
		return okx && oky &&
			(xk.PrivateKey.priv == yk.PrivateKey.priv) &&
			xk.PrivateKey.PublicKey.Equal(yk.PrivateKey.PublicKey)
	},

	publicEqual: func(x, y Node) bool {
		xk, okx := x.(*DHNode)
		yk, oky := y.(*DHNode)
		return okx && oky && xk.PrivateKey.PublicKey.Equal(yk.PrivateKey.PublicKey)
	},

	combine: func(x, y Node) (Node, error) {
		xk, okx := x.(*DHNode)
		yk, oky := y.(*DHNode)
		if !okx || !oky {
			return nil, InvalidNodeError
		}

		switch {
		case xk.isBlank:
			return yk, nil
		case yk.isBlank:
			return xk, nil
		case xk.hasPrivate:
			return DHNodeFromData(xk.PrivateKey.derive(yk.PrivateKey.PublicKey)), nil
		case yk.hasPrivate:
			return DHNodeFromData(yk.PrivateKey.derive(xk.PrivateKey.PublicKey)), nil
		default:
			return nil, IncompatibleNodesError
		}
	},
}

type DHPath []DHPublicKey

func NewDHPath(f []Node) (DHPath, error) {
	ecp := make(DHPath, len(f))
	for i, e := range f {
		if !dhNodeDefn.valid(e) {
			return nil, InvalidNodeError
		}

		ecp[i] = e.(*DHNode).PrivateKey.PublicKey
	}

	return ecp, nil
}

func (ecp DHPath) Nodes() []Node {
	f := make([]Node, len(ecp))
	for i, e := range ecp {
		f[i] = DHNodeFromPublicKey(e)
	}

	return f
}
