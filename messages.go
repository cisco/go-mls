package mls

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type UserPreKey struct {
	PreKey ECPublicKey
}

type GroupPreKey struct {
	Epoch            uint
	GroupID          []byte
	GroupSize        uint
	UpdateKey        ECPublicKey
	IdentityFrontier MerkleFrontier
	LeafFrontier     MerkleFrontier
	RatchetFrontier  ECFrontier
}

type UserAdd struct {
	AddPath []ECPublicKey
}

type GroupAdd struct {
	PreKey *Signed
}

type Update struct {
	LeafPath    [][]byte
	RatchetPath []ECPublicKey
}

type Delete struct {
	Deleted    []uint
	Path       []ECPublicKey
	Leaves     []ECPublicKey
	Identities [][]byte
}

// Signed
type Signed struct {
	Encoded   []byte
	PublicKey ECPublicKey
	Signature []byte
}

func NewSigned(message interface{}, key ECPrivateKey) (*Signed, error) {
	encoded, err := json.Marshal(message)
	if err != nil {
		return nil, err
	}

	signature, err := key.sign(encoded)
	if err != nil {
		return nil, err
	}

	return &Signed{
		Encoded:   encoded,
		PublicKey: key.PublicKey,
		Signature: signature,
	}, nil
}

func (s Signed) Verify(out interface{}) error {
	if !s.PublicKey.verify(s.Encoded, s.Signature) {
		return fmt.Errorf("Invalid signature")
	}

	if out == nil {
		return nil
	}

	return json.Unmarshal(s.Encoded, out)
}

// RosterSigned
type RosterSigned struct {
	Signed
	Size   uint
	Index  uint
	Copath MerkleCopath
}

func NewRosterSigned(message interface{}, key ECPrivateKey, index, size uint, copath []Node) (*RosterSigned, error) {
	merkle, err := NewMerkleCopath(copath)
	if err != nil {
		return nil, err
	}

	signed, err := NewSigned(message, key)
	if err != nil {
		return nil, err
	}

	return &RosterSigned{
		Size:   size,
		Index:  index,
		Signed: *signed,
		Copath: merkle,
	}, nil
}

func (s RosterSigned) Verify(out interface{}, expectedRoot []byte) error {
	if expectedRoot != nil {
		leaf := merkleLeaf(s.Signed.PublicKey.bytes())
		root, err := s.Copath.Root(s.Index, s.Size, leaf)
		if err != nil {
			return err
		}

		if !bytes.Equal(root, expectedRoot) {
			return fmt.Errorf("Merkle inclusion check failed")
		}
	}

	return s.Signed.Verify(out)
}
