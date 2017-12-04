package mls

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type UserPreKey struct {
	LeafKey ECKey
}

type GroupPreKey struct {
	Epoch                uint
	GroupID              []byte
	UpdateKey            *ECKey
	IdentityTreeFrontier MerkleFrontier
	LeafTreeFrontier     MerkleFrontier
	RatchetTreeFrontier  ECFrontier
}

type UserAdd struct {
	AddPath []*ECKey
}

type GroupAdd struct {
	PreKey    Signed
	UpdateKey *ECKey
}

type Update struct {
	LeafPath    [][]byte
	RatchetPath []*ECKey
}

type Delete struct {
	Deleted    []uint
	Path       []*ECKey
	Leaves     []*ECKey
	Identities [][]byte
}

// Signed
type Signed struct {
	Encoded   []byte
	PublicKey *ECKey
	Signature []byte
}

func NewSigned(message interface{}, key *ECKey) (*Signed, error) {
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
		PublicKey: key,
		Signature: signature,
	}, nil
}

func (s Signed) Verify(out interface{}) error {
	if !s.PublicKey.verify(s.Encoded, s.Signature) {
		return fmt.Errorf("Invalid signature")
	}

	return json.Unmarshal(s.Encoded, out)
}

// RosterSigned
type RosterSigned struct {
	Signed
	Copath MerkleCopath
}

func NewRosterSigned(message interface{}, key *ECKey, copath *Copath) (*RosterSigned, error) {
	merkle, err := NewMerkleCopath(copath)
	if err != nil {
		return nil, err
	}

	signed, err := NewSigned(message, key)
	if err != nil {
		return nil, err
	}

	return &RosterSigned{
		Signed: *signed,
		Copath: *merkle,
	}, nil
}

func (s RosterSigned) Verify(out interface{}, expectedRoot []byte) error {
	leaf := merkleLeaf(s.Signed.PublicKey.bytes())
	root, err := s.Copath.Root(leaf)
	if err != nil {
		return err
	}

	if !bytes.Equal(root, expectedRoot) {
		return fmt.Errorf("Merkle inclusion check failed")
	}

	return s.Signed.Verify(out)
}
