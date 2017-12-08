package mls

import (
	"encoding/json"
	"github.com/bifurcation/mint/syntax"
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

	aIdentityLeaf    = MerkleNodeFromPublicKey(aPublicKey)
	aIdentityRoot, _ = merkleNodeDefn.combine(aIdentityLeaf, aIdentityLeaf)

	aUserPreKey = &UserPreKey{
		PreKey:      aPublicKey,
		IdentityKey: aPublicKey,
		Signature:   aData,
	}

	aGroupPreKey = &GroupPreKey{
		Epoch:            2,
		GroupID:          []byte{0x00, 0x01, 0x02, 0x03},
		GroupSize:        2,
		UpdateKey:        aPublicKey,
		IdentityFrontier: aMerklePath,
		LeafFrontier:     aMerklePath,
		RatchetFrontier:  aECPath,
	}

	aNone = &None{}

	aUserAdd = &UserAdd{AddPath: []ECPublicKey{aPublicKey, aPublicKey}}

	aGroupAdd = &GroupAdd{
		PreKey: *aUserPreKey,
	}

	aUpdate = &Update{
		LeafPath:    aMerklePath,
		RatchetPath: aECPath,
	}

	aDelete = &Delete{
		Deleted:    []uint32{0, 1},
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
	testJSON(aNone, new(None))
	testJSON(aUserAdd, new(UserAdd))
	testJSON(aGroupAdd, new(GroupAdd))
	testJSON(aUpdate, new(Update))
	testJSON(aDelete, new(Delete))
}

func TestMessageTLS(t *testing.T) {
	testTLS := func(label string, x interface{}, out interface{}) {
		t.Logf(label)
		xj, err := syntax.Marshal(x)
		if err != nil {
			t.Fatalf("Error in TLS marshal: %v", err)
		}

		_, err = syntax.Unmarshal(xj, out)
		if err != nil {
			t.Fatalf("Error in TLS unmarshal: %v", err)
		}

		if !reflect.DeepEqual(x, out) {
			t.Fatalf("JSON round-trip failed: %+v != %+v", x, out)
		}
	}

	testTLS("UserPreKey", aUserPreKey, new(UserPreKey))
	testTLS("GroupPreKey", aGroupPreKey, new(GroupPreKey))
	testTLS("None", aNone, new(None))
	testTLS("UserAdd", aUserAdd, new(UserAdd))
	testTLS("GroupAdd", aGroupAdd, new(GroupAdd))
	testTLS("Update", aUpdate, new(Update))
	testTLS("Delete", aDelete, new(Delete))
}

func TestUserPreKeySignVerify(t *testing.T) {
	identityKey := NewECPrivateKey()
	_, upk, err := NewUserPreKey(identityKey)
	if err != nil {
		t.Fatalf("Error in UserPreKey signing: %v", err)
	}

	if err := upk.Verify(); err != nil {
		t.Fatalf("Error in UserPreKey verification: %v", err)
	}
}

func TestHandshakeSignMarshalUnmarshalVerify(t *testing.T) {
	handshake := &Handshake{
		PreKey:        *aGroupPreKey,
		SignerIndex:   0,
		IdentityProof: MerklePath{MerkleNodeFromPublicKey(aPublicKey)},
	}

	testHandshake := func(label string, x HandshakeMessageBody, out interface{}) {
		t.Logf(label)

		handshake.Body = x

		err := handshake.Sign(aPrivateKey)
		if err != nil {
			t.Fatalf("Error in sign: %v", err)
		}

		xj, err := syntax.Marshal(x)
		if err != nil {
			t.Fatalf("Error in TLS marshal: %v", err)
		}

		_, err = syntax.Unmarshal(xj, out)
		if err != nil {
			t.Fatalf("Error in TLS unmarshal: %v", err)
		}

		err = handshake.Verify(aIdentityRoot)
		if err != nil {
			t.Fatalf("Error in verify: %v", err)
		}

		if !reflect.DeepEqual(x, out) {
			t.Fatalf("JSON round-trip failed: %+v != %+v", x, out)
		}
	}

	testHandshake("None", aNone, new(None))
	testHandshake("UserAdd", aUserAdd, new(UserAdd))
	testHandshake("GroupAdd", aGroupAdd, new(GroupAdd))
	testHandshake("Update", aUpdate, new(Update))
	testHandshake("Delete", aDelete, new(Delete))
}
