package mls

import (
	"github.com/bifurcation/mint/syntax"
	"testing"
)

// todo: refactor common variables if we decide to add more tests in this category
// todo: we eventually need tests to verify welcome processing as part of state impln

func deriveGroupKeyAndNonce(suite CipherSuite, initSecret []byte) keyAndNonce {
	secretSize := suite.constants().SecretSize
	keySize := suite.constants().KeySize
	nonceSize := suite.constants().NonceSize

	groupInfoSecret := suite.hkdfExpandLabel(initSecret, "group info", []byte{}, secretSize)
	groupInfoKey := suite.hkdfExpandLabel(groupInfoSecret, "key", []byte{}, keySize)
	groupInfoNonce := suite.hkdfExpandLabel(groupInfoSecret, "nonce", []byte{}, nonceSize)

	return keyAndNonce{
		Key:   groupInfoKey,
		Nonce: groupInfoNonce,
	}
}

func TestWelcomeMarshalUnMarshal(t *testing.T) {
	// a tree with 2 members
	treeAB := newTestRatchetTree(t, supportedSuites[0], [][]byte{secretA, secretB}, []Credential{credA, credB})
	assertTrue(t, treeAB.size() == 2, "size mismatch")
	assertEquals(t, *treeAB.GetCredential(leafIndex(0)), credA)
	assertEquals(t, *treeAB.GetCredential(leafIndex(1)), credB)

	cs := supportedSuites[0]
	secret, _ := getRandomBytes(32)
	dp, _ := treeAB.Encap(leafIndex(0), []byte{}, secret)

	// setup things needed to welcome c
	priv, _ := cs.hpke().Derive(secretC)
	pub := priv.PublicKey
	cik, _ := syntax.Marshal(clientInitKey)
	cikHash := cs.digest(cik)

	initSecret := []byte("we welcome you c")
	kp := KeyPackage{
		InitSecret: initSecret,
	}
	pt, _ := syntax.Marshal(kp)
	ep, err := cs.hpke().Encrypt(pub, []byte{}, pt)
	if err != nil {
		t.Fatalf("encrpyting to c's public key failed")
	}

	ekp := EncryptedKeyPackage{
		ClientInitKeyHash: cikHash,
		EncryptedPackage:  ep,
	}

	gi := GroupInfo{
		GroupId:                      unhex("0007"),
		Epoch:                        121,
		TreeHash:                     treeAB.RootHash(),
		Tree:                         treeAB,
		PriorConfirmedTranscriptHash: []byte{0x00, 0x01, 0x02, 0x03},
		ConfirmedTranscriptHash:      []byte{0x03, 0x04, 0x05, 0x06},
		InterimTranscriptHash:        []byte{0x02, 0x03, 0x04, 0x05},
		Path:                         dp,
		SignerIndex:                  0,
		Confirmation:                 []byte{0x00, 0x00, 0x00, 0x00},
		Signature:                    []byte{0xAA, 0xBB, 0xCC},
	}

	pt, err = syntax.Marshal(gi)
	if err != nil {
		t.Fatalf("groupInfo marshal fail %v", err)
	}
	kn := deriveGroupKeyAndNonce(cs, initSecret)
	aead, err := cs.newAEAD(kn.Key)
	if err != nil {
		t.Fatalf("Error creating AEAD: %v", err)
	}
	encrypted := aead.Seal(nil, kn.Nonce, pt, []byte{})

	w := &Welcome{
		Version:             0,
		CipherSuite:         cs,
		EncryptedKeyPackage: ekp,
		EncryptedGroupInfo:  encrypted,
	}

	t.Run("WelcomeOneMember", roundTrip(w, new(Welcome)))
}
