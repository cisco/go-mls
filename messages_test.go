package mls

import (
	"bytes"
	"testing"

	"github.com/bifurcation/mint/syntax"
	"github.com/stretchr/testify/require"
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

	keyPackage = &KeyPackage{
		SupportedVersion: SupportedVersionMLS10,
		CipherSuite:      0x0001,
		InitKey:          ikPriv.PublicKey,
		Credential:       credentialBasic,
		//Extensions:       extListValidIn,
		Signature: Signature{[]byte{0x00, 0x00, 0x00}},
	}

	addProposal = &Proposal{
		Add: &AddProposal{
			KeyPackage: *keyPackage,
		},
	}

	removeProposal = &Proposal{
		Remove: &RemoveProposal{
			Removed: 12,
		},
	}

	updateProposal = &Proposal{
		Update: &UpdateProposal{
			KeyPackage: *keyPackage,
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
		Updates:    []ProposalID{{Hash: []byte{0x00, 0x01}}},
		Removes:    []ProposalID{{Hash: []byte{0x02, 0x03}}},
		Adds:       []ProposalID{{Hash: []byte{0x04, 0x05}}},
		KeyPackage: *keyPackage,
		Path:       DirectPath{Nodes: nodes},
	}

	mlsPlaintextIn = &MLSPlaintext{
		GroupID:           []byte{0x01, 0x02, 0x03, 0x04},
		Epoch:             1,
		Sender:            Sender{SenderTypeMember, 4},
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
)

func roundTrip(original interface{}, decoded interface{}) func(t *testing.T) {
	return func(t *testing.T) {
		encoded, err := syntax.Marshal(original)
		require.Nil(t, err)

		_, err = syntax.Unmarshal(encoded, decoded)
		require.Nil(t, err)
		require.Equal(t, decoded, original)
	}
}

func TestMessagesMarshalUnmarshal(t *testing.T) {
	t.Run("BasicCredential", roundTrip(&credentialBasic, new(Credential)))
	t.Run("KeyPackage", roundTrip(keyPackage, new(KeyPackage)))
	t.Run("AddProposal", roundTrip(addProposal, new(Proposal)))
	t.Run("RemoveProposal", roundTrip(removeProposal, new(Proposal)))
	t.Run("UpdateProposal", roundTrip(updateProposal, new(Proposal)))
	t.Run("Commit", roundTrip(commit, new(Commit)))
	t.Run("MLSPlaintextContentApplication", roundTrip(mlsPlaintextIn, new(MLSPlaintext)))
	t.Run("MLSCiphertext", roundTrip(mlsCiphertextIn, new(MLSCiphertext)))
}

func TestWelcomeMarshalUnMarshalWithDecryption(t *testing.T) {
	// a tree with 2 members
	groupSize := 2
	secrets := [][]byte{randomBytes(32), randomBytes(32)}
	treeAB := newTestRatchetTree(t, suite, secrets)
	require.Equal(t, treeAB.size(), leafCount(groupSize))

	cs := supportedSuites[0]
	secret := randomBytes(32)

	// setup things needed to welcome c
	epochSecret := []byte("we welcome you c")
	gi := &GroupInfo{
		GroupID:                 unhex("0007"),
		Epoch:                   121,
		Tree:                    *treeAB,
		ConfirmedTranscriptHash: []byte{0x03, 0x04, 0x05, 0x06},
		InterimTranscriptHash:   []byte{0x02, 0x03, 0x04, 0x05},
		SignerIndex:             0,
		Confirmation:            []byte{0x00, 0x00, 0x00, 0x00},
		Signature:               []byte{0xAA, 0xBB, 0xCC},
	}

	w1 := newWelcome(cs, epochSecret, gi)
	w1.EncryptTo(*keyPackage, secret)
	// doing this so that test can omit this field when matching w1, w2
	w1.epochSecret = nil
	w2 := new(Welcome)
	t.Run("WelcomeOneMember", roundTrip(w1, w2))

	// decrypt the group init secret with C's privateKey and check if
	// it matches.
	egs := w2.Secrets[0]
	pt, err := cs.hpke().Decrypt(ikPriv, []byte{}, egs.EncryptedGroupSecrets)
	require.Nil(t, err)

	w2kp := new(GroupSecrets)
	_, err = syntax.Unmarshal(pt, w2kp)
	require.Nil(t, err)
	require.Equal(t, epochSecret, w2kp.EpochSecret)
}

///
/// Test Vectors
///

type MessageTestCase struct {
	CipherSuite     CipherSuite
	SignatureScheme SignatureScheme

	KeyPackage            []byte `tls:"head=4"`
	GroupInfo             []byte `tls:"head=4"`
	GroupSecrets          []byte `tls:"head=4"`
	EncryptedGroupSecrets []byte `tls:"head=4"`
	Welcome               []byte `tls:"head=4"`
	AddProposal           []byte `tls:"head=4"`
	UpdateProposal        []byte `tls:"head=4"`
	RemoveProposal        []byte `tls:"head=4"`
	Commit                []byte `tls:"head=4"`
	MLSCiphertext         []byte `tls:"head=4"`
}

type MessageTestVectors struct {
	Epoch        Epoch
	SenderType   SenderType
	SignerIndex  leafIndex
	Removed      leafIndex
	UserId       []byte            `tls:"head=1"`
	GroupID      []byte            `tls:"head=1"`
	KeyPackageId []byte            `tls:"head=1"`
	DHSeed       []byte            `tls:"head=1"`
	SigSeed      []byte            `tls:"head=1"`
	Random       []byte            `tls:"head=1"`
	Cases        []MessageTestCase `tls:"head=4"`
}

/// Gen and Verify
func generateMessageVectors(t *testing.T) []byte {
	tv := MessageTestVectors{
		Epoch:        0xA0A1A2A3,
		SenderType:   SenderTypeMember,
		SignerIndex:  leafIndex(0xB0B1B2B3),
		Removed:      leafIndex(0xC0C1C2C3),
		UserId:       bytes.Repeat([]byte{0xD1}, 16),
		GroupID:      bytes.Repeat([]byte{0xD2}, 16),
		KeyPackageId: bytes.Repeat([]byte{0xD3}, 16),
		DHSeed:       bytes.Repeat([]byte{0xD4}, 32),
		SigSeed:      bytes.Repeat([]byte{0xD5}, 32),
		Random:       bytes.Repeat([]byte{0xD6}, 32),
		Cases:        []MessageTestCase{},
	}

	suites := []CipherSuite{P256_AES128GCM_SHA256_P256, X25519_AES128GCM_SHA256_Ed25519}
	schemes := []SignatureScheme{ECDSA_SECP256R1_SHA256, Ed25519}

	for i := range suites {
		suite := suites[i]
		scheme := schemes[i]
		// hpke
		priv, err := suite.hpke().Derive(tv.DHSeed)
		require.Nil(t, err)
		pub := priv.PublicKey

		// identity
		sigPriv, err := scheme.Derive(tv.SigSeed)
		require.Nil(t, err)
		sigPub := sigPriv.PublicKey

		bc := &BasicCredential{
			Identity:           tv.UserId,
			SignatureScheme:    scheme,
			SignaturePublicKey: sigPub,
		}
		cred := Credential{Basic: bc}

		secrets := [][]byte{tv.Random, tv.Random, tv.Random, tv.Random}
		ratchetTree := newTestRatchetTree(t, suite, secrets)

		err = ratchetTree.BlankPath(leafIndex(2))
		require.Nil(t, err)

		dp, _, err := ratchetTree.Encap(leafIndex(0), []byte{}, tv.Random)
		require.Nil(t, err)

		// KeyPackage
		kp := KeyPackage{
			SupportedVersion: SupportedVersionMLS10,
			CipherSuite:      suite,
			InitKey:          pub,
			Credential:       cred,
			Signature:        Signature{tv.Random},
		}

		kpM, err := syntax.Marshal(kp)
		require.Nil(t, err)

		// Welcome

		gi := &GroupInfo{
			GroupID:                 tv.GroupID,
			Epoch:                   tv.Epoch,
			Tree:                    *ratchetTree,
			ConfirmedTranscriptHash: tv.Random,
			InterimTranscriptHash:   tv.Random,
			Confirmation:            tv.Random,
			SignerIndex:             tv.SignerIndex,
			Signature:               tv.Random,
		}

		giM, err := syntax.Marshal(gi)
		require.Nil(t, err)

		gs := GroupSecrets{
			EpochSecret: tv.Random,
		}

		gsM, err := syntax.Marshal(gs)
		require.Nil(t, err)

		encPayload, err := suite.hpke().Encrypt(pub, []byte{}, tv.Random)
		require.Nil(t, err)
		egs := EncryptedGroupSecrets{
			KeyPackageHash:        tv.Random,
			EncryptedGroupSecrets: encPayload,
		}

		egsM, err := syntax.Marshal(egs)
		require.Nil(t, err)

		var welcome Welcome
		welcome.Version = SupportedVersionMLS10
		welcome.CipherSuite = suite
		welcome.Secrets = []EncryptedGroupSecrets{egs, egs}
		welcome.EncryptedGroupInfo = tv.Random

		welM, err := syntax.Marshal(welcome)
		require.Nil(t, err)

		// proposals
		addProposal := &Proposal{
			Add: &AddProposal{
				KeyPackage: kp,
			},
		}

		addHs := MLSPlaintext{
			GroupID: tv.GroupID,
			Epoch:   tv.Epoch,
			Sender:  Sender{tv.SenderType, uint32(tv.SignerIndex)},
			Content: MLSPlaintextContent{
				Proposal: addProposal,
			},
		}
		addHs.Signature = Signature{tv.Random}

		addM, err := syntax.Marshal(addHs)
		require.Nil(t, err)

		updateProposal := &Proposal{
			Update: &UpdateProposal{
				KeyPackage: kp,
			},
		}

		updateHs := MLSPlaintext{
			GroupID: tv.GroupID,
			Epoch:   tv.Epoch,
			Sender:  Sender{tv.SenderType, uint32(tv.SignerIndex)},
			Content: MLSPlaintextContent{
				Proposal: updateProposal,
			},
		}
		updateHs.Signature = Signature{tv.Random}

		updateM, err := syntax.Marshal(updateHs)
		require.Nil(t, err)

		removeProposal := &Proposal{
			Remove: &RemoveProposal{
				Removed: tv.SignerIndex,
			},
		}

		removeHs := MLSPlaintext{
			GroupID: tv.GroupID,
			Epoch:   tv.Epoch,
			Sender:  Sender{tv.SenderType, uint32(tv.SignerIndex)},
			Content: MLSPlaintextContent{
				Proposal: removeProposal,
			},
		}
		removeHs.Signature = Signature{tv.Random}

		remM, err := syntax.Marshal(removeHs)
		require.Nil(t, err)

		// commit
		proposal := []ProposalID{{tv.Random}, {tv.Random}}
		commit := Commit{
			Updates:    proposal,
			Removes:    proposal,
			Adds:       proposal,
			KeyPackage: kp,
			Path:       dp,
		}

		commitM, err := syntax.Marshal(commit)
		require.Nil(t, err)

		//MlsCiphertext
		ct := MLSCiphertext{
			GroupID:             tv.GroupID,
			Epoch:               tv.Epoch,
			ContentType:         ContentTypeApplication,
			SenderDataNonce:     tv.Random,
			EncryptedSenderData: tv.Random,
			AuthenticatedData:   tv.Random,
		}

		ctM, err := syntax.Marshal(ct)
		require.Nil(t, err)

		tc := MessageTestCase{
			CipherSuite:           suite,
			SignatureScheme:       scheme,
			KeyPackage:            kpM,
			GroupInfo:             giM,
			GroupSecrets:          gsM,
			EncryptedGroupSecrets: egsM,
			Welcome:               welM,
			AddProposal:           addM,
			UpdateProposal:        updateM,
			RemoveProposal:        remM,
			Commit:                commitM,
			MLSCiphertext:         ctM,
		}
		tv.Cases = append(tv.Cases, tc)
	}

	vec, err := syntax.Marshal(tv)
	require.Nil(t, err)
	return vec
}

func verifyMessageVectors(t *testing.T, data []byte) {
	var tv MessageTestVectors
	_, err := syntax.Unmarshal(data, &tv)
	require.Nil(t, err)

	for _, tc := range tv.Cases {
		suite := tc.CipherSuite
		scheme := tc.SignatureScheme
		priv, err := suite.hpke().Derive(tv.DHSeed)
		require.Nil(t, err)
		pub := priv.PublicKey

		sigPriv, err := scheme.Derive(tv.SigSeed)
		require.Nil(t, err)
		sigPub := sigPriv.PublicKey

		bc := &BasicCredential{
			Identity:           tv.UserId,
			SignatureScheme:    scheme,
			SignaturePublicKey: sigPub,
		}
		cred := Credential{Basic: bc}

		secrets := [][]byte{tv.Random, tv.Random, tv.Random, tv.Random}
		ratchetTree := newTestRatchetTree(t, suite, secrets)

		err = ratchetTree.BlankPath(leafIndex(2))
		require.Nil(t, err)

		dp, _, err := ratchetTree.Encap(leafIndex(0), []byte{}, tv.Random)
		require.Nil(t, err)

		// KeyPackage
		kp := KeyPackage{
			SupportedVersion: SupportedVersionMLS10,
			CipherSuite:      suite,
			InitKey:          pub,
			Credential:       cred,
			Signature:        Signature{tv.Random},
		}
		kpM, err := syntax.Marshal(kp)
		require.Nil(t, err)
		require.Equal(t, kpM, tc.KeyPackage)

		// Welcome
		var gi GroupInfo
		gi.Tree.Suite = suite
		_, err = syntax.Unmarshal(tc.GroupInfo, &gi)
		require.Nil(t, err)

		marshaled, err := syntax.Marshal(gi)
		require.Nil(t, err)
		require.Equal(t, marshaled, tc.GroupInfo)

		gs := GroupSecrets{
			EpochSecret: tv.Random,
		}

		gsM, err := syntax.Marshal(gs)
		require.Nil(t, err)
		require.Equal(t, gsM, tc.GroupSecrets)

		encPayload, err := suite.hpke().Encrypt(pub, []byte{}, tv.Random)
		require.Nil(t, err)
		egs := EncryptedGroupSecrets{
			KeyPackageHash:        tv.Random,
			EncryptedGroupSecrets: encPayload,
		}
		var egsWire EncryptedGroupSecrets
		syntax.Unmarshal(tc.EncryptedGroupSecrets, &egsWire)
		require.Equal(t, egs.KeyPackageHash, egsWire.KeyPackageHash)

		var welcome Welcome
		welcome.Version = SupportedVersionMLS10
		welcome.CipherSuite = suite
		welcome.Secrets = []EncryptedGroupSecrets{egs, egs}
		welcome.EncryptedGroupInfo = tv.Random

		var welWire Welcome
		syntax.Unmarshal(tc.Welcome, &welWire)
		require.Equal(t, welcome.CipherSuite, welWire.CipherSuite)
		require.Equal(t, welcome.Version, welWire.Version)
		require.Equal(t, welcome.EncryptedGroupInfo, welWire.EncryptedGroupInfo)

		// proposals
		addProposal := &Proposal{
			Add: &AddProposal{
				KeyPackage: kp,
			},
		}

		addHs := MLSPlaintext{
			GroupID: tv.GroupID,
			Epoch:   tv.Epoch,
			Sender:  Sender{tv.SenderType, uint32(tv.SignerIndex)},
			Content: MLSPlaintextContent{
				Proposal: addProposal,
			},
		}
		addHs.Signature = Signature{tv.Random}

		addM, err := syntax.Marshal(addHs)
		require.Nil(t, err)
		require.Equal(t, addM, tc.AddProposal)

		updateProposal := &Proposal{
			Update: &UpdateProposal{
				KeyPackage: kp,
			},
		}

		updateHs := MLSPlaintext{
			GroupID: tv.GroupID,
			Epoch:   tv.Epoch,
			Sender:  Sender{tv.SenderType, uint32(tv.SignerIndex)},
			Content: MLSPlaintextContent{
				Proposal: updateProposal,
			},
		}
		updateHs.Signature = Signature{tv.Random}

		updateM, err := syntax.Marshal(updateHs)
		require.Nil(t, err)
		require.Equal(t, updateM, tc.UpdateProposal)

		removeProposal := &Proposal{
			Remove: &RemoveProposal{
				Removed: tv.SignerIndex,
			},
		}

		removeHs := MLSPlaintext{
			GroupID: tv.GroupID,
			Epoch:   tv.Epoch,
			Sender:  Sender{tv.SenderType, uint32(tv.SignerIndex)},
			Content: MLSPlaintextContent{
				Proposal: removeProposal,
			},
		}
		removeHs.Signature = Signature{tv.Random}
		remM, err := syntax.Marshal(removeHs)
		require.Nil(t, err)
		require.Equal(t, remM, tc.RemoveProposal)

		// commit
		proposal := []ProposalID{{tv.Random}, {tv.Random}}
		commit := Commit{
			Updates:    proposal,
			Removes:    proposal,
			Adds:       proposal,
			KeyPackage: kp,
			Path:       dp,
		}
		var commitWire Commit
		_, err = syntax.Unmarshal(tc.Commit, &commitWire)
		require.Nil(t, err)
		require.Equal(t, commit.Adds, commitWire.Adds)
		require.Equal(t, commit.Removes, commitWire.Removes)
		require.Equal(t, commit.Updates, commitWire.Updates)
		require.Equal(t, commit.KeyPackage, commitWire.KeyPackage)
		// Path not verified because HPKE is randomized

		//MlsCiphertext
		ct := MLSCiphertext{
			GroupID:             tv.GroupID,
			Epoch:               tv.Epoch,
			ContentType:         ContentTypeApplication,
			SenderDataNonce:     tv.Random,
			EncryptedSenderData: tv.Random,
			AuthenticatedData:   tv.Random,
		}

		ctM, err := syntax.Marshal(ct)
		require.Nil(t, err)
		require.Equal(t, ctM, tc.MLSCiphertext)
	}
}
