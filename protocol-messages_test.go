package mls

import (
	"github.com/bifurcation/mint/syntax"
	"reflect"
	"testing"
)

var (
	sigPrivateKey = NewSignaturePrivateKey()
	sigPublicKey  = aSigPrivateKey.PublicKey

	basicCredential = &BasicCredential{
		Identity:           []byte{0x01, 0x02, 0x03, 0x04},
		SignatureScheme:    0x0403,
		SignaturePublicKey: sigPublicKey.pub,
	}

	credentialBasic = Credential{
		CredentialType: CredentialTypeBasic,
		Basic:          basicCredential,
	}

	extIn = Extension{
		ExtensionType: ExtensionType(0x0001),
		ExtensionData: []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4},
	}

	extEmpty = Extension{
		ExtensionType: ExtensionType(0x0002),
		ExtensionData: []byte{},
	}

	extListIn = ExtensionList{extIn, extEmpty}

	extValidIn = Extension{
		ExtensionType: ExtensionType(0x000a),
		ExtensionData: []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4},
	}
	extEmptyIn = Extension{
		ExtensionType: ExtensionType(0x000a),
		ExtensionData: []byte{},
	}

	extListValidIn = ExtensionList{extValidIn, extEmptyIn}

	initKey = HPKEPublicKey{
		Data: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
	}

	sign = Signature{
		Data: []byte{0x00, 0x00, 0x00},
	}

	clientInitKey = &ClientInitKey{
		SupportedVersion: 0xFF,
		CipherSuite:     0x0001,
		InitKey:         initKey,
		Credential:      credentialBasic,
		Extensions:      extListValidIn,
		Signature:       sign,
	}

	addProposal = &Proposal{
		Type: ProposalTypeAdd,
		Add: &AddProposal{
			ClientInitKey: *clientInitKey,
		},
	}

	removeProposal = &Proposal{
		Type: ProposalTypeRemove,
		Remove: &RemoveProposal{
			Removed: 12,
		},
	}

	updateProposal = &Proposal{
		Type: ProposalTypeUpdate,
		Update: &UpdateProposal{
			LeafKey: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
		},
	}

	nodePublicKey = HPKEPublicKey{
		Data: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
	}

	nodes = []RatchetTreeNode{
		{
			PublicKey: nodePublicKey,
		},
	}

	commits = &Commit{
		Updates: []ProposalId{
			{
			Sender: 4,
			Hash:   []byte{0x01, 0x03},
			},
	    },
		Adds: ProposalId{
			Sender: 8,
			Hash:   []byte{0x07, 0x09},
		},
		Path: &DirectPath{
			Nodes: nodes,
		},
	}

	mlsPlainTextIn = &MLSPlainText{
		GroupId:           []byte{0x01, 0x02, 0x03, 0x04},
		Epoch:             1,
		Sender:            4,
		ContentType:       ContentTypeApplication,
		AuthenticatedData: []byte{0xAA, 0xBB, 0xcc, 0xdd},
		Application: &ApplicationData{
			Data: []byte{0x0A, 0x0B, 0x0C, 0x0D},
		},
		Signature: []byte{0x00, 0x01, 0x02, 0x03},
	}

	mlsCiphertextIn = &MLSCipherText{
		GroupId:             []byte{0x01, 0x02, 0x03, 0x04},
		Epoch:               1,
		ContentType:         1,
		SenderDataNonce:     []byte{0x01, 0x02},
		EncryptedSenderData: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
		CipherText:          []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
	}
)

func TestMLSMessagesMarshalUnMarshal(t *testing.T) {

	testMLS := func(label string, x interface{}, out interface{}) {
		t.Logf(label)
		encoded, err := syntax.Marshal(x)
		if err != nil {
			t.Fatalf("Fail to Marshal Valid: %s, %v", label, err)
		}

		_, err = syntax.Unmarshal(encoded, out)
		if err != nil {
			t.Fatalf("Fail to unmarshal: %v", err)
		}

		if !reflect.DeepEqual(x, out) {
			t.Fatalf("Mismatch input vs output: %+v != %+v", x, out)
		}
	}

	testMLS("ClientInitKey", clientInitKey, new(ClientInitKey))
	testMLS("AddProposal", addProposal, new(Proposal))
	testMLS("RemoveProposal", removeProposal, new(Proposal))
	testMLS("UpdateProposal", updateProposal, new(Proposal))
	testMLS("MLSPlainTextContentApplication", mlsPlainTextIn, new(MLSPlainText))
	testMLS("MLSCipherText", mlsCiphertextIn, new(MLSCipherText))
}
