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
