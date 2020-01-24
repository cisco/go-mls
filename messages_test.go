package mls

import (
	"bytes"
	"github.com/bifurcation/mint/syntax"
	"testing"
)

var (
	sigPublicKey    = SignaturePublicKey{[]byte{0xA0, 0xA0, 0xA0, 0xA0}}
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

	ikPriv, _ = supportedSuites[0].hpke().Generate()

	clientInitKey = &ClientInitKey{
		SupportedVersion: SupportedVersionMLS10,
		CipherSuite:      0x0001,
		InitKey:          ikPriv.PublicKey,
		Credential:       credentialBasic,
		//Extensions:       extListValidIn,
		Signature: Signature{[]byte{0x00, 0x00, 0x00}},
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
			PublicKey:            nodePublicKey,
			EncryptedPathSecrets: []HPKECiphertext{},
		},
	}

	commit = &Commit{
		Updates: []ProposalID{{Hash: []byte{0x00, 0x01}}},
		Removes: []ProposalID{{Hash: []byte{0x02, 0x03}}},
		Adds:    []ProposalID{{Hash: []byte{0x04, 0x05}}},
		Ignored: []ProposalID{{Hash: []byte{0x06, 0x07}}},
		Path:    DirectPath{Nodes: nodes},
	}

	mlsPlaintextIn = &MLSPlaintext{
		GroupID:           []byte{0x01, 0x02, 0x03, 0x04},
		Epoch:             1,
		Sender:            4,
		AuthenticatedData: []byte{0xAA, 0xBB, 0xcc, 0xdd},
		Content: MLSPlaintextContent{
			Application: &ApplicationData{
				Data: []byte{0x0A, 0x0B, 0x0C, 0x0D},
			},
		},
		Signature: Signature{[]byte{0x00, 0x01, 0x02, 0x03}},
	}

	mlsCiphertextIn = &MLSCiphertext{
		GroupID:             []byte{0x01, 0x02, 0x03, 0x04},
		Epoch:               1,
		ContentType:         1,
		AuthenticatedData:   []byte{0xAA, 0xBB, 0xCC},
		SenderDataNonce:     []byte{0x01, 0x02},
		EncryptedSenderData: []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
		Ciphertext:          []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16},
	}

	priv, _          = supportedSuites[0].hpke().Derive(secretA)
	rtnNilCredential = &RatchetTreeNode{
		Credential:     nil,
		PublicKey:      &priv.PublicKey,
		UnmergedLeaves: []leafIndex{leafIndex(1)},
	}

	rtnWithCredential = &RatchetTreeNode{
		Credential:     &credentialBasic,
		PublicKey:      &priv.PublicKey,
		UnmergedLeaves: []leafIndex{leafIndex(1)},
	}

	ortnRtnNilCred = &OptionalRatchetNode{
		Node: rtnNilCredential,
	}

	ortnRtnCred = &OptionalRatchetNode{
		Node: rtnWithCredential,
	}

	ratchetTree = &RatchetTree{
		Nodes:       []OptionalRatchetNode{*ortnRtnCred},
		CipherSuite: supportedSuites[0],
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
	t.Run("Commit", roundTrip(commit, new(Commit)))
	t.Run("MLSPlaintextContentApplication", roundTrip(mlsPlaintextIn, new(MLSPlaintext)))
	t.Run("MLSCiphertext", roundTrip(mlsCiphertextIn, new(MLSCiphertext)))
	t.Run("RatchetTreeNodeNilCredential", roundTrip(rtnNilCredential, new(RatchetTreeNode)))
	t.Run("RatchetTreeNodeWithCredential", roundTrip(rtnWithCredential, new(RatchetTreeNode)))
	t.Run("OptionalRatchetTreeNodeWithCredential", roundTrip(ortnRtnNilCred, new(OptionalRatchetNode)))
	t.Run("LeafNodeHashInputWithNilInfo", roundTrip(leafNodeWithNilInfo, new(LeafNodeHashInput)))
	t.Run("LeafNodeHashInputWithInfo", roundTrip(leafNodeWithInfo, new(LeafNodeHashInput)))
}

func TestWelcomeMarshalUnMarshalWithDecryption(t *testing.T) {
	// a tree with 2 members
	treeAB := newTestRatchetTree(t, supportedSuites[0], [][]byte{secretA, secretB}, []Credential{credA, credB})
	assertTrue(t, treeAB.size() == 2, "size mismatch")
	assertEquals(t, *treeAB.GetCredential(leafIndex(0)), credA)
	assertEquals(t, *treeAB.GetCredential(leafIndex(1)), credB)

	cs := supportedSuites[0]
	secret, _ := getRandomBytes(32)
	dp, _ := treeAB.Encap(leafIndex(0), []byte{}, secret)

	// setup things needed to welcome c
	initSecret := []byte("we welcome you c")
	gi := &GroupInfo{
		GroupId:                      unhex("0007"),
		Epoch:                        121,
		Tree:                         treeAB,
		PriorConfirmedTranscriptHash: []byte{0x00, 0x01, 0x02, 0x03},
		ConfirmedTranscriptHash:      []byte{0x03, 0x04, 0x05, 0x06},
		InterimTranscriptHash:        []byte{0x02, 0x03, 0x04, 0x05},
		Path:                         dp,
		SignerIndex:                  0,
		Confirmation:                 []byte{0x00, 0x00, 0x00, 0x00},
		Signature:                    []byte{0xAA, 0xBB, 0xCC},
	}

	w1 := newWelcome(cs, initSecret, gi, []ClientInitKey{*clientInitKey})
	// doing this so that test can omit this field when matching w1, w2
	w1.initSecret = nil
	w2 := new(Welcome)
	t.Run("WelcomeOneMember", roundTrip(w1, w2))

	// decrypt the group init secret with C's privateKey and check if
	// it matches.
	ekp := w2.EncryptedKeyPackages[0]
	pt, err := cs.hpke().Decrypt(ikPriv, []byte{}, ekp.EncryptedPackage)
	assertNotError(t, err, "decryption error")

	w2kp := new(KeyPackage)
	_, err = syntax.Unmarshal(pt, w2kp)
	assertNotError(t, err, "unmarshal failure for decrypted KeyPackage")
	assertByteEquals(t, initSecret, w2kp.InitSecret)
}

///
/// Test Vectors
///

type MessageTestCase struct {
	CipherSuite     CipherSuite
	SignatureScheme SignatureScheme

	ClientInitKey       []byte `tls:"head=4"`
	GroupInfo           []byte `tls:"head=4"`
	KeyPackage          []byte `tls:"head=4"`
	EncryptedKeyPackage []byte `tls:"head=4"`
	Welcome             []byte `tls:"head=4"`
	AddProposal         []byte `tls:"head=4"`
	UpdateProposal      []byte `tls:"head=4"`
	RemoveProposal      []byte `tls:"head=4"`
	Commit              []byte `tls:"head=4"`
	MLSCiphertext       []byte `tls:"head=4"`
}

type MessageTestVectors struct {
	Epoch           Epoch
	SingerIndex     leafIndex
	Removed         leafIndex
	UserId          []byte            `tls:"head=1"`
	GroupId         []byte            `tls:"head=1"`
	ClientInitKeyId []byte            `tls:"head=1"`
	DHSeed          []byte            `tls:"head=1"`
	SigSeed         []byte            `tls:"head=1"`
	Random          []byte            `tls:"head=1"`
	Cases           []MessageTestCase `tls:"head=4"`
}

//helpers

func groupInfoMatch(t *testing.T, l, r GroupInfo) {
	assertByteEquals(t, l.GroupId, r.GroupId)
	assertEquals(t, l.Epoch, r.Epoch)
	assertTrue(t, l.Tree.Equals(r.Tree), "tree unequal")
	assertByteEquals(t, l.PriorConfirmedTranscriptHash, r.PriorConfirmedTranscriptHash)
	assertByteEquals(t, l.ConfirmedTranscriptHash, r.ConfirmedTranscriptHash)
	assertByteEquals(t, l.InterimTranscriptHash, r.InterimTranscriptHash)
	assertByteEquals(t, l.Confirmation, r.Confirmation)
	assertEquals(t, l.SignerIndex, r.SignerIndex)
	assertByteEquals(t, l.Signature, r.Signature)
}

func commitMatch(t *testing.T, l, r Commit) {
	assertDeepEquals(t, l.Adds, r.Adds)
	assertDeepEquals(t, l.Removes, r.Removes)
	assertDeepEquals(t, l.Updates, r.Updates)
	assertDeepEquals(t, l.Ignored, r.Ignored)
}

/// Gen and Verify
func generateMessageVectors(t *testing.T) []byte {
	tv := MessageTestVectors{
		Epoch:           0xA0A1A2A3,
		SingerIndex:     leafIndex(0xB0B1B2B3),
		Removed:         leafIndex(0xC0C1C2C3),
		UserId:          bytes.Repeat([]byte{0xD1}, 16),
		GroupId:         bytes.Repeat([]byte{0xD2}, 16),
		ClientInitKeyId: bytes.Repeat([]byte{0xD3}, 16),
		DHSeed:          bytes.Repeat([]byte{0xD4}, 32),
		SigSeed:         bytes.Repeat([]byte{0xD5}, 32),
		Random:          bytes.Repeat([]byte{0xD6}, 32),
		Cases:           []MessageTestCase{},
	}

	suites := []CipherSuite{P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM}
	schemes := []SignatureScheme{ECDSA_SECP256R1_SHA256, Ed25519}

	for i := range suites {
		suite := suites[i]
		scheme := schemes[i]
		// hpke
		priv, err := suite.hpke().Derive(tv.DHSeed)
		assertNotError(t, err, "priv key failure")
		pub := priv.PublicKey

		// identity
		sigPriv, err := scheme.Derive(tv.SigSeed)
		assertNotError(t, err, "sigPriv failure")
		sigPub := sigPriv.PublicKey

		bc := &BasicCredential{
			Identity:           tv.UserId,
			SignatureScheme:    scheme,
			SignaturePublicKey: sigPub,
		}
		cred := Credential{Basic: bc}

		ratchetTree := newTestRatchetTree(t, suite,
			[][]byte{tv.Random, tv.Random, tv.Random, tv.Random},
			[]Credential{cred, cred, cred, cred})

		err = ratchetTree.BlankPath(leafIndex(2), true)
		assertNotError(t, err, "rtree blank path")

		dp, _ := ratchetTree.Encap(leafIndex(0), []byte{}, tv.Random)

		// CIK
		cik := ClientInitKey{
			SupportedVersion: SupportedVersionMLS10,
			CipherSuite:      suite,
			InitKey:          pub,
			Credential:       cred,
			Signature:        Signature{tv.Random},
		}

		cikM, err := syntax.Marshal(cik)
		assertNotError(t, err, "cik marshal")

		// Welcome

		gi := newGroupInfo(tv.GroupId, tv.Epoch, *ratchetTree, tv.Random)
		gi.SignerIndex = tv.SingerIndex
		gi.Path = dp
		gi.ConfirmedTranscriptHash = tv.Random
		gi.InterimTranscriptHash = tv.Random
		gi.Confirmation = tv.Random
		gi.Signature = tv.Random

		giM, err := syntax.Marshal(gi)
		assertNotError(t, err, "grpInfo marshal")

		kp := KeyPackage{
			InitSecret: tv.Random,
		}

		kpM, err := syntax.Marshal(kp)
		assertNotError(t, err, "keyy package marshal")

		encPayload, err := suite.hpke().Encrypt(pub, []byte{}, tv.Random)
		assertNotError(t, err, "encrypt ekp")
		ekp := EncryptedKeyPackage{
			ClientInitKeyHash: tv.Random,
			EncryptedPackage:  encPayload,
		}

		ekpM, err := syntax.Marshal(ekp)
		assertNotError(t, err, "encrypted key package marshal")

		var welcome Welcome
		welcome.Version = SupportedVersionMLS10
		welcome.CipherSuite = suite
		welcome.EncryptedKeyPackages = []EncryptedKeyPackage{ekp, ekp}
		welcome.EncryptedGroupInfo = tv.Random

		welM, err := syntax.Marshal(welcome)
		assertNotError(t, err, "welcome marshal")

		// proposals
		addProposal := &Proposal{
			Add: &AddProposal{
				ClientInitKey: cik,
			},
		}

		addHs := MLSPlaintext{
			GroupID: tv.GroupId,
			Epoch:   tv.Epoch,
			Sender:  tv.SingerIndex,
			Content: MLSPlaintextContent{
				Proposal: addProposal,
			},
		}
		addHs.Signature = Signature{tv.Random}

		addM, err := syntax.Marshal(addHs)
		assertNotError(t, err, "add HS marshal")

		updateProposal := &Proposal{
			Update: &UpdateProposal{
				LeafKey: pub,
			},
		}

		updateHs := MLSPlaintext{
			GroupID: tv.GroupId,
			Epoch:   tv.Epoch,
			Sender:  tv.SingerIndex,
			Content: MLSPlaintextContent{
				Proposal: updateProposal,
			},
		}
		updateHs.Signature = Signature{tv.Random}

		updateM, err := syntax.Marshal(updateHs)
		assertNotError(t, err, "update HS marshal")

		removeProposal := &Proposal{
			Remove: &RemoveProposal{
				Removed: tv.SingerIndex,
			},
		}

		removeHs := MLSPlaintext{
			GroupID: tv.GroupId,
			Epoch:   tv.Epoch,
			Sender:  tv.SingerIndex,
			Content: MLSPlaintextContent{
				Proposal: removeProposal,
			},
		}
		removeHs.Signature = Signature{tv.Random}

		remM, err := syntax.Marshal(removeHs)
		assertNotError(t, err, "remove HS marshal")

		// commit
		proposal := []ProposalID{{tv.Random}, {tv.Random}}
		commit := Commit{
			Updates: proposal,
			Removes: proposal,
			Adds:    proposal,
			Ignored: proposal,
		}

		commitM, err := syntax.Marshal(commit)
		assertNotError(t, err, "commit marshal")

		//MlsCiphertext
		ct := MLSCiphertext{
			GroupID:             tv.GroupId,
			Epoch:               tv.Epoch,
			ContentType:         ContentTypeApplication,
			SenderDataNonce:     tv.Random,
			EncryptedSenderData: tv.Random,
			AuthenticatedData:   tv.Random,
		}

		ctM, err := syntax.Marshal(ct)
		assertNotError(t, err, "MLSCiphertext marshal")

		tc := MessageTestCase{
			CipherSuite:         suite,
			SignatureScheme:     scheme,
			ClientInitKey:       cikM,
			GroupInfo:           giM,
			KeyPackage:          kpM,
			EncryptedKeyPackage: ekpM,
			Welcome:             welM,
			AddProposal:         addM,
			UpdateProposal:      updateM,
			RemoveProposal:      remM,
			Commit:              commitM,
			MLSCiphertext:       ctM,
		}
		tv.Cases = append(tv.Cases, tc)
	}

	vec, err := syntax.Marshal(tv)
	assertNotError(t, err, "Error marshaling test vectors")
	return vec
}

func verifyMessageVectors(t *testing.T, data []byte) {
	var tv MessageTestVectors
	_, err := syntax.Unmarshal(data, &tv)
	assertNotError(t, err, "Malformed message test vectors")

	for _, tc := range tv.Cases {
		suite := tc.CipherSuite
		scheme := tc.SignatureScheme
		priv, err := suite.hpke().Derive(tv.DHSeed)
		assertNotError(t, err, "hpke error")
		pub := priv.PublicKey

		sigPriv, err := scheme.Derive(tv.SigSeed)
		assertNotError(t, err, "sig error")
		sigPub := sigPriv.PublicKey

		bc := &BasicCredential{
			Identity:           tv.UserId,
			SignatureScheme:    scheme,
			SignaturePublicKey: sigPub,
		}
		cred := Credential{Basic: bc}

		ratchetTree := newTestRatchetTree(t, suite,
			[][]byte{tv.Random, tv.Random, tv.Random, tv.Random},
			[]Credential{cred, cred, cred, cred})

		err = ratchetTree.BlankPath(leafIndex(2), true)
		assertNotError(t, err, "rtree blank path")

		dp, _ := ratchetTree.Encap(leafIndex(0), []byte{}, tv.Random)

		// CIK
		cik := ClientInitKey{
			SupportedVersion: SupportedVersionMLS10,
			CipherSuite:      suite,
			InitKey:          pub,
			Credential:       cred,
			Signature:        Signature{tv.Random},
		}
		cikM, err := syntax.Marshal(cik)
		assertNotError(t, err, "cik marshal")
		assertByteEquals(t, cikM, tc.ClientInitKey)

		// Welcome
		gi := newGroupInfo(tv.GroupId, tv.Epoch, *ratchetTree, tv.Random)
		gi.SignerIndex = tv.SingerIndex
		gi.Path = dp
		gi.ConfirmedTranscriptHash = tv.Random
		gi.InterimTranscriptHash = tv.Random
		gi.Confirmation = tv.Random
		gi.Signature = tv.Random

		var giWire GroupInfo
		_, err = syntax.Unmarshal(tc.GroupInfo, &giWire)
		assertNotError(t, err, "groupInfo unmarshal")

		groupInfoMatch(t, *gi, giWire)

		kp := KeyPackage{
			InitSecret: tv.Random,
		}

		kpM, err := syntax.Marshal(kp)
		assertNotError(t, err, "key package marshal")
		assertByteEquals(t, kpM, tc.KeyPackage)

		encPayload, err := suite.hpke().Encrypt(pub, []byte{}, tv.Random)
		assertNotError(t, err, "encrypt ekp")
		ekp := EncryptedKeyPackage{
			ClientInitKeyHash: tv.Random,
			EncryptedPackage:  encPayload,
		}
		var ekpWire EncryptedKeyPackage
		syntax.Unmarshal(tc.EncryptedKeyPackage, &ekpWire)
		assertByteEquals(t, ekp.ClientInitKeyHash, ekpWire.ClientInitKeyHash)

		var welcome Welcome
		welcome.Version = SupportedVersionMLS10
		welcome.CipherSuite = suite
		welcome.EncryptedKeyPackages = []EncryptedKeyPackage{ekp, ekp}
		welcome.EncryptedGroupInfo = tv.Random

		var welWire Welcome
		syntax.Unmarshal(tc.Welcome, &welWire)
		assertTrue(t, welcome.CipherSuite == welWire.CipherSuite, "welcome suite")
		assertTrue(t, welcome.Version == welWire.Version, "welcome version")
		assertByteEquals(t, welcome.EncryptedGroupInfo, welWire.EncryptedGroupInfo)

		// proposals
		addProposal := &Proposal{
			Add: &AddProposal{
				ClientInitKey: cik,
			},
		}

		addHs := MLSPlaintext{
			GroupID: tv.GroupId,
			Epoch:   tv.Epoch,
			Sender:  tv.SingerIndex,
			Content: MLSPlaintextContent{
				Proposal: addProposal,
			},
		}
		addHs.Signature = Signature{tv.Random}

		addM, err := syntax.Marshal(addHs)
		assertNotError(t, err, "add HS marshal")
		assertByteEquals(t, addM, tc.AddProposal)

		updateProposal := &Proposal{
			Update: &UpdateProposal{
				LeafKey: pub,
			},
		}

		updateHs := MLSPlaintext{
			GroupID: tv.GroupId,
			Epoch:   tv.Epoch,
			Sender:  tv.SingerIndex,
			Content: MLSPlaintextContent{
				Proposal: updateProposal,
			},
		}
		updateHs.Signature = Signature{tv.Random}

		updateM, err := syntax.Marshal(updateHs)
		assertNotError(t, err, "update HS marshal")
		assertByteEquals(t, updateM, tc.UpdateProposal)

		removeProposal := &Proposal{
			Remove: &RemoveProposal{
				Removed: tv.SingerIndex,
			},
		}

		removeHs := MLSPlaintext{
			GroupID: tv.GroupId,
			Epoch:   tv.Epoch,
			Sender:  tv.SingerIndex,
			Content: MLSPlaintextContent{
				Proposal: removeProposal,
			},
		}
		removeHs.Signature = Signature{tv.Random}
		remM, err := syntax.Marshal(removeHs)
		assertNotError(t, err, "remove HS marshal")
		assertByteEquals(t, remM, tc.RemoveProposal)

		// commit
		proposal := []ProposalID{{tv.Random}, {tv.Random}}
		commit := Commit{
			Updates: proposal,
			Removes: proposal,
			Adds:    proposal,
			Ignored: proposal,
			Path:    *dp,
		}
		var commitWire Commit
		_, err = syntax.Unmarshal(tc.Commit, &commitWire)
		assertNotError(t, err, "commit marshal")
		commitMatch(t, commit, commitWire)

		//MlsCiphertext
		ct := MLSCiphertext{
			GroupID:             tv.GroupId,
			Epoch:               tv.Epoch,
			ContentType:         ContentTypeApplication,
			SenderDataNonce:     tv.Random,
			EncryptedSenderData: tv.Random,
			AuthenticatedData:   tv.Random,
		}

		ctM, err := syntax.Marshal(ct)
		assertNotError(t, err, "MLSCiphertext marshal")
		assertByteEquals(t, ctM, tc.MLSCiphertext)
	}
}
