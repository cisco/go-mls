package mls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"
)

var (
	aData          = []byte("messages")
	aPrivateKey, _ = ecdsa.GenerateKey(ecdhCurve, rand.Reader)
	aKey           = ECKeyFromPublicKey(&aPrivateKey.PublicKey)
	aMerkleEntry   = MerkleFrontierEntry{Value: aData, Size: 4}
	aECEntry       = ECFrontierEntry{Value: aKey, Size: 4}

	aUserPreKey = &UserPreKey{LeafKey: *aKey}

	aGroupPreKey = &GroupPreKey{
		Epoch:                2,
		GroupID:              []byte{0x00, 0x01, 0x02, 0x03},
		UpdateKey:            aKey,
		IdentityTreeFrontier: MerkleFrontier{aMerkleEntry, aMerkleEntry},
		LeafTreeFrontier:     MerkleFrontier{aMerkleEntry, aMerkleEntry},
		RatchetTreeFrontier:  ECFrontier{aECEntry, aECEntry},
	}

	aUserAdd = &UserAdd{AddPath: []*ECKey{aKey, aKey}}

	aGroupAdd = &GroupAdd{
		PreKey:    Signed{},
		UpdateKey: aKey,
	}

	aUpdate = &Update{
		LeafPath:    [][]byte{aData, aData},
		RatchetPath: []*ECKey{aKey, aKey},
	}

	aDelete = &Delete{
		Deleted:    []uint{0, 1},
		Path:       []*ECKey{aKey, aKey},
		Leaves:     []*ECKey{aKey, aKey},
		Identities: [][]byte{aData, aData},
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
	k := ECKeyFromData([]byte("signing test"))

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
	aGroupSize := 7
	aLeafKeys := make([]*ECKey, aGroupSize)
	aLeaves := make([]Node, aGroupSize)
	for i := range aLeafKeys {
		aLeafKeys[i] = NewECKey()
		aLeaves[i] = merkleLeaf(aLeafKeys[i].bytes())
	}

	aTree, err := newTreeFromLeaves(merkleNodeDefn, aLeaves)
	if err != nil {
		t.Fatalf("Error generating Merkle tree: %v", err)
	}

	rootNode, err := aTree.Root()
	if err != nil {
		t.Fatalf("Error fetching root: %v", err)
	}

	expectedRoot := rootNode.([]byte)

	for i, k := range aLeafKeys {
		in := aUserPreKey
		c, err := aTree.Copath(uint(i))
		if err != nil {
			t.Fatalf("Error fetching copath @ %d: %v", i, err)
		}

		rs, err := NewRosterSigned(in, k, c)
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
