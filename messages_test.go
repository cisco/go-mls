package mls

import (
	"github.com/bifurcation/mint/syntax"
	"reflect"
	"testing"
)

var (
	aData          = []byte("messages")
	aSigPrivateKey = NewSignaturePrivateKey()
	aSigPublicKey  = aSigPrivateKey.PublicKey

	aDHPrivateKey = NewDHPrivateKey()
	aDHPublicKey  = aDHPrivateKey.PublicKey

	aMerkleNode = MerkleNode{aData}
	aMerklePath = MerklePath{aMerkleNode, aMerkleNode}

	aDHPath = DHPath{aDHPublicKey, aDHPublicKey}

	aIdentityLeaf    = NewMerkleNode(aSigPublicKey)
	aIdentityRoot, _ = merkleNodeDefn.combine(aIdentityLeaf, aIdentityLeaf)

	aUserPreKey = &UserPreKey{
		PreKey:      aDHPublicKey,
		IdentityKey: aSigPublicKey,
		Signature:   aData,
	}

	aGroupPreKey = &GroupPreKey{
		Epoch:            2,
		GroupID:          []byte{0x00, 0x01, 0x02, 0x03},
		GroupSize:        2,
		UpdateKey:        aDHPublicKey,
		IdentityFrontier: aMerklePath,
		LeafFrontier:     aMerklePath,
		RatchetFrontier:  aDHPath,
	}

	aNone = &None{}

	aUserAdd = &UserAdd{AddPath: []DHPublicKey{aDHPublicKey, aDHPublicKey}}

	aGroupAdd = &GroupAdd{
		PreKey: *aUserPreKey,
	}

	aUpdate = &Update{
		LeafPath:    aMerklePath,
		RatchetPath: aDHPath,
	}

	aDelete = &Delete{
		Deleted:    []uint32{0, 1},
		Path:       aDHPath,
		Leaves:     aDHPath,
		Identities: aMerklePath,
	}
)

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
			t.Fatalf("TLS round-trip failed: %+v != %+v", x, out)
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
	identityKey := NewSignaturePrivateKey()
	_, upk, err := NewUserPreKey(identityKey)
	if err != nil {
		t.Fatalf("Error in UserPreKey signing: %v", err)
	}

	if err := upk.Verify(); err != nil {
		t.Fatalf("Error in UserPreKey verification: %v", err)
	}
}

func TestHandshakeSignMarshalUnmarshalVerify(t *testing.T) {
	original := &Handshake{
		PreKey:        *aGroupPreKey,
		SignerIndex:   0,
		IdentityProof: MerklePath{NewMerkleNode(aSigPublicKey)},
	}

	testHandshake := func(label string, body HandshakeMessageBody) {
		t.Logf(label)

		original.Body = body

		err := original.Sign(aSigPrivateKey)
		if err != nil {
			t.Fatalf("Error in sign: %v", err)
		}

		encoded, err := syntax.Marshal(original)
		if err != nil {
			t.Fatalf("Error in TLS marshal: %v", err)
		}

		decoded := new(Handshake)
		_, err = syntax.Unmarshal(encoded, decoded)
		if err != nil {
			t.Fatalf("Error in TLS unmarshal: %v", err)
		}

		err = decoded.Verify(aIdentityRoot)
		if err != nil {
			t.Fatalf("Error in verify: %v", err)
		}

		if !reflect.DeepEqual(original, decoded) {
			t.Fatalf("Sign/Marshal/Unmarshal/Verify round-trip failed: %+v != %+v", original, decoded)
		}
	}

	testHandshake("None", aNone)
	testHandshake("UserAdd", aUserAdd)
	testHandshake("GroupAdd", aGroupAdd)
	testHandshake("Update", aUpdate)
	testHandshake("Delete", aDelete)
}
