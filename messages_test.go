package mls

import (
	"encoding/json"
	"reflect"
	"testing"
)

var (
	aData       = []byte("messages")
	aPrivateKey = NewECPrivateKey()
	aMerkleNode = MerkleNode{aData}
	aMerklePath = MerklePath{aMerkleNode, aMerkleNode}
	aPublicKey  = aPrivateKey.PublicKey
	aECPath     = ECPath{aPublicKey, aPublicKey}

	aUserPreKey = &UserPreKey{PreKey: aPublicKey}

	aGroupPreKey = &GroupPreKey{
		Epoch:            2,
		GroupID:          []byte{0x00, 0x01, 0x02, 0x03},
		UpdateKey:        aPublicKey,
		IdentityFrontier: aMerklePath,
		LeafFrontier:     aMerklePath,
		RatchetFrontier:  aECPath,
	}

	aUserAdd = &UserAdd{AddPath: []ECPublicKey{aPublicKey, aPublicKey}}

	aSignedUserPreKey, _ = NewSigned(aUserPreKey, aPrivateKey)
	aGroupAdd            = &GroupAdd{
		PreKey: aSignedUserPreKey,
	}

	aUpdate = &Update{
		LeafPath:    aMerklePath,
		RatchetPath: aECPath,
	}

	aDelete = &Delete{
		Deleted:    []uint{0, 1},
		Path:       aECPath,
		Leaves:     aECPath,
		Identities: aMerklePath,
	}
)

func TestMessageJSON(t *testing.T) {
	testJSON := func(x interface{}, out interface{}) {
		xj, err := json.Marshal(x)
		if err != nil {
			t.Fatalf("Error in JSON marshal: %v", err)
		}

		err = json.Unmarshal(xj, out)
		if err != nil {
			t.Fatalf("Error in JSON unmarshal: %v", err)
		}

		if !reflect.DeepEqual(x, out) {
			t.Fatalf("JSON round-trip failed: %+v != %+v", x, out)
		}
	}

	testJSON(aUserPreKey, new(UserPreKey))
	testJSON(aGroupPreKey, new(GroupPreKey))
	testJSON(aUserAdd, new(UserAdd))
	testJSON(aGroupAdd, new(GroupAdd))
	testJSON(aUpdate, new(Update))
	testJSON(aDelete, new(Delete))
}

func TestSigned(t *testing.T) {
	k := ECNodeFromData([]byte("signing test")).PrivateKey

	in := aUserPreKey
	s, err := NewSigned(in, k)
	if err != nil {
		t.Fatalf("Error in signing: %v", err)
	}

	sj, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("Error in JSON marshal: %v", err)
	}

	s2 := new(Signed)
	err = json.Unmarshal(sj, s2)
	if err != nil {
		t.Fatalf("Error in JSON unmarshal: %v", err)
	}

	out := new(UserPreKey)
	err = s2.Verify(out)
	if err != nil {
		t.Fatalf("Error in verification: %v", err)
	}

	if !reflect.DeepEqual(in, out) {
		t.Fatalf("Sign/verify round-trip failed: %+v != %+v", in, out)
	}
}

func TestRosterSigned(t *testing.T) {
	aGroupSize := uint(7)
	aLeafKeys := make([]ECPrivateKey, aGroupSize)
	aLeaves := make([]Node, aGroupSize)
	for i := range aLeafKeys {
		aLeafKeys[i] = NewECPrivateKey()
		aLeaves[i] = MerkleNodeFromPublicKey(aLeafKeys[i].PublicKey)
	}

	aTree, err := newTreeFromLeaves(merkleNodeDefn, aLeaves)
	if err != nil {
		t.Fatalf("Error generating Merkle tree: %v", err)
	}

	rootNode, err := aTree.Root()
	if err != nil {
		t.Fatalf("Error fetching root: %v", err)
	}

	expectedRoot := rootNode.(MerkleNode).Value

	for i, k := range aLeafKeys {
		in := aUserPreKey
		c, err := aTree.Copath(uint(i))
		if err != nil {
			t.Fatalf("Error fetching copath @ %d: %v", i, err)
		}

		rs, err := NewRosterSigned(in, k, uint(i), aGroupSize, c)
		if err != nil {
			t.Fatalf("Error in roster-signing @ %d: %v", i, err)
		}

		rsj, err := json.Marshal(rs)
		if err != nil {
			t.Fatalf("Error in JSON marshal @ %d: %v", i, err)
		}

		rs2 := new(RosterSigned)
		err = json.Unmarshal(rsj, rs2)
		if err != nil {
			t.Fatalf("Error in JSON unmarshal @ %d: %v", i, err)
		}

		out := new(UserPreKey)
		err = rs2.Verify(out, expectedRoot)
		if err != nil {
			t.Fatalf("Error in verifying roster-signed @ %d: %v", i, err)
		}
	}
}
