package mls

import (
	"github.com/bifurcation/mint/syntax"
	"testing"
)

var (
	sigPublicKey = SignaturePublicKey{[]byte{0xA0, 0xA0, 0xA0, 0xA0}}

	basicCredential = &BasicCredential{
		Identity:           []byte{0x01, 0x02, 0x03, 0x04},
		SignatureScheme:    0x0403,
		SignaturePublicKey: sigPublicKey,
	}

	credentialBasic = Credential{
		Basic: basicCredential,
	}

	extIn = Extension{
		ExtensionType: ExtensionType(0x0001),
		ExtensionData: []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4},
	}

	extEmpty = Extension{
		ExtensionType: ExtensionType(0x0002),
		ExtensionData: []byte{},
	}

	extListIn = ExtensionList{[]Extension{extIn, extEmpty}}

	extValidIn = Extension{
		ExtensionType: ExtensionType(0x000a),
		ExtensionData: []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4},
	}
	extEmptyIn = Extension{
		ExtensionType: ExtensionType(0x000a),
		ExtensionData: []byte{},
	}

	extListValidIn = ExtensionList{[]Extension{extValidIn, extEmptyIn}}

	initKey = HPKEPublicKey{
		Data: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
	}

	clientInitKey = &ClientInitKey{
		SupportedVersion: 0xFF,
		CipherSuite:      0x0001,
		InitKey:          initKey,
		Credential:       credentialBasic,
		Extensions:       extListValidIn,
		Signature:        []byte{0x00, 0x00, 0x00},
	}

	addProposal = &Proposal{
		Add: &AddProposal{
			ClientInitKey: *clientInitKey,
		},
	}

	removeProposal = &Proposal{
		Remove: &RemoveProposal{
			Removed: 12,
		},
	}

	updateProposal = &Proposal{
		Update: &UpdateProposal{
			LeafKey: HPKEPublicKey{[]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16}},
		},
	}

	nodePublicKey = HPKEPublicKey{
		Data: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
	}

	nodes = []DirectPathNode{
		{
			PublicKey: nodePublicKey,
		},
	}

	commits = &Commit{
		Updates: []ProposalID{
			{
				Sender: 4,
				Hash:   []byte{0x01, 0x03},
			},
		},
		Adds: ProposalID{
			Sender: 8,
			Hash:   []byte{0x07, 0x09},
		},
		Path: &DirectPath{
			Nodes: nodes,
		},
	}

	mlsPlainTextIn = &MLSPlainText{
		GroupID:           []byte{0x01, 0x02, 0x03, 0x04},
		Epoch:             1,
		Sender:            4,
		AuthenticatedData: []byte{0xAA, 0xBB, 0xcc, 0xdd},
		Content: MLSPlaintextContent{
			Application: &ApplicationData{
				Data: []byte{0x0A, 0x0B, 0x0C, 0x0D},
			},
		},
		Signature: []byte{0x00, 0x01, 0x02, 0x03},
	}

	mlsCiphertextIn = &MLSCipherText{
		GroupID:             []byte{0x01, 0x02, 0x03, 0x04},
		Epoch:               1,
		ContentType:         1,
		SenderDataNonce:     []byte{0x01, 0x02},
		EncryptedSenderData: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
		CipherText:          []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
	}

	priv, _          = supportedSuites[0].hpke().Derive(secretA)
	rtnNilCredential = &RatchetTreeNode{
		Cred:           nil,
		PublicKey:      &priv.PublicKey,
		PrivateKey:     &priv,
		UnmergedLeaves: []leafIndex{leafIndex(1)},
		CipherSuite:    supportedSuites[0],
	}

	rtnWithCredential = &RatchetTreeNode{
		Cred:           &credentialBasic,
		PublicKey:      &priv.PublicKey,
		PrivateKey:     &priv,
		UnmergedLeaves: []leafIndex{leafIndex(1)},
		CipherSuite:    supportedSuites[0],
	}

	ortnRtnNilCred = &OptionalRatchetNode{
		Node: rtnNilCredential,
		hash: nil,
	}

	rachetTree = &RatchetTree{
		Nodes:       []OptionalRatchetNode{*ortnRtnNilCred},
		CipherSuite: supportedSuites[0],
		NumLeaves:   1,
	}

	leafNodeWithNilInfo = &LeafNodeHashInput{
		HashType: 0,
		Info:     nil,
	}

	leafNodeWithInfo = &LeafNodeHashInput{
		HashType: 0,
		Info: &LeafNodeInfo{
			Credential: credA,
			PublicKey:  priv.PublicKey,
		},
	}
)

func roundTrip(original interface{}, decoded interface{}) func(t *testing.T) {
	return func(t *testing.T) {
		encoded, err := syntax.Marshal(original)
		assertNotError(t, err, "Fail to Marshal")

		_, err = syntax.Unmarshal(encoded, decoded)
		assertNotError(t, err, "Fail to Unmarshal")
		assertDeepEquals(t, decoded, original)
	}
}

func TestMessagesMarshalUnmarshal(t *testing.T) {
	t.Run("ClientInitKey", roundTrip(clientInitKey, new(ClientInitKey)))
	t.Run("AddProposal", roundTrip(addProposal, new(Proposal)))
	t.Run("RemoveProposal", roundTrip(removeProposal, new(Proposal)))
	t.Run("UpdateProposal", roundTrip(updateProposal, new(Proposal)))
	t.Run("MLSPlainTextContentApplication", roundTrip(mlsPlainTextIn, new(MLSPlainText)))
	t.Run("MLSCipherText", roundTrip(mlsCiphertextIn, new(MLSCipherText)))
	t.Run("RatchetTreeNodeNilCredential", roundTrip(rtnNilCredential, new(RatchetTreeNode)))
	t.Run("RatchetTreeNodeWithCredential", roundTrip(rtnWithCredential, new(RatchetTreeNode)))
	t.Run("OptionalRatchetTreeNodeWithCredential", roundTrip(ortnRtnNilCred, new(OptionalRatchetNode)))
	t.Run("RatchetTree", roundTrip(rachetTree, new(RatchetTree)))
	t.Run("LeafNodeHashInputWithNilInfo", roundTrip(leafNodeWithNilInfo, new(LeafNodeHashInput)))
	t.Run("LeafNodeHashInputWithInfo", roundTrip(leafNodeWithInfo, new(LeafNodeHashInput)))
}
