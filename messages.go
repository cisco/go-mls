package mls

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/bifurcation/mint/syntax"
)

// struct {
//     CipherSuite cipher_suites<0..255>;
//     DHPublicKey pre_key;
//     SignaturePublicKey identity_key;
//     SignatureScheme algorithm;
//     opaque signature<0..2^16-1>;
// } UserPreKey;
//
// TODO(rlb@ipv.sx): Add credentials
// TODO(rlb@ipv.sx): Crypto agility
//
// TODO(right now): Align this with the struct above
type UserPreKey struct {
	PreKey      ECPublicKey
	IdentityKey ECPublicKey
	Signature   []byte `tls:"head=2"`
}

func NewUserPreKey(identityKey ECPrivateKey) (priv ECPrivateKey, upk *UserPreKey, err error) {
	priv = NewECPrivateKey()
	upk = &UserPreKey{
		PreKey:      priv.PublicKey,
		IdentityKey: identityKey.PublicKey,
		Signature:   nil,
	}

	tbs, err := syntax.Marshal(upk)
	if err != nil {
		return
	}

	// Strip the signature header octets
	tbs = tbs[:len(tbs)-2]

	upk.Signature, err = identityKey.sign(tbs)
	return
}

func (upk UserPreKey) Verify() error {
	tbs, err := syntax.Marshal(upk)
	if err != nil {
		return err
	}
	tbs = tbs[:len(tbs)-len(upk.Signature)-2]

	if !upk.IdentityKey.verify(tbs, upk.Signature) {
		return fmt.Errorf("Invalid signature")
	}

	return nil
}

// struct {
//     uint32 epoch;
//     uint32 group_size;
//     opaque group_id<0..2^16-1>;
//     DHPublicKey update_key;
//     MerkleNode identityFrontier<0..2^16-1>;
//     MerkleNode leafFrontier<0..2^16-1>;
//     DHPublicKey ratchetFrontier<0..2^16-1>;
// } GroupPreKey;
type GroupPreKey struct {
	Epoch            uint32
	GroupID          []byte `tls:"head=2"`
	GroupSize        uint32
	UpdateKey        ECPublicKey
	IdentityFrontier MerklePath `tls:"min=1,head=2"`
	LeafFrontier     MerklePath `tls:"min=1,head=2"`
	RatchetFrontier  ECPath     `tls:"min=1,head=2"`
}

// struct {
//     DHPublicKey add_path<1..2^16-1>;
// } UserAdd;
type UserAdd struct {
	AddPath []ECPublicKey `tls:"min=1,head=2"`
}

// struct {
//     UserPreKey pre_key;
// } GroupAdd;
type GroupAdd struct {
	PreKey UserPreKey
}

// struct {
//     MerkleNode leafPath<1..2^16-1>;
//     DHPublicKey ratchetPath<1..2^16-1>;
// } Update;
type Update struct {
	LeafPath    MerklePath `tls:"min=1,head=2"`
	RatchetPath ECPath     `tls:"min=1,head=2"`
}

// struct {
//     uint32 deleted<1..2^16-1>;
//     DHPublicKey path<1..2^16-1>;
//     DHPublicKey leaves<1..2^16-1>;
//     MerkleNode hashed_identities<1..2^16-1>;
// } Delete;
type Delete struct {
	Deleted    []uint32   `tls:"min=1,head=2"`
	Path       ECPath     `tls:"min=1,head=2"`
	Leaves     ECPath     `tls:"min=1,head=2"`
	Identities MerklePath `tls:"min=1,head=2"`
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
	Copath MerklePath
}

func NewRosterSigned(message interface{}, key ECPrivateKey, index, size uint, copath []Node) (*RosterSigned, error) {
	merkle, err := NewMerklePath(copath)
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
		leaf := MerkleNodeFromPublicKey(s.Signed.PublicKey)
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
