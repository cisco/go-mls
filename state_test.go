package mls

import (
	"fmt"
	"testing"
)

var (
	groupId   = []byte{0x01, 0x02, 0x03, 0x04}
	userId    = []byte{0x04, 0x05, 0x06, 0x07}
	suite     = P256_SHA256_AES128GCM
	scheme    = Ed25519
	groupSize = 5
	setupDone = false

	identityPrivs  []SignaturePrivateKey
	credentials    []Credential
	initPrivs      []HPKEPrivateKey
	clientInitKeys = make([]ClientInitKey, groupSize)
	states         []State

	testMessage = unhex("1112131415")
)

func newBasicCredential(userId []byte, scheme SignatureScheme) Credential {
	sigPriv, _ := scheme.Generate()
	basicCredential = &BasicCredential{
		Identity:           userId,
		SignatureScheme:    scheme,
		SignaturePublicKey: sigPriv.PublicKey,
	}
	credentialBasic = Credential{Basic: basicCredential, privateKey: &sigPriv}
	return credentialBasic
}

func setup(t *testing.T) {
	if setupDone {
		return
	}

	for i := 0; i < groupSize; i++ {
		// cred gen
		credentialBasic = newBasicCredential(userId, scheme)
		//cik gen
		cik, err := newClientInitKey(suite, &credentialBasic)
		assertNotError(t, err, "newClientInitKey error")
		// save all the materials
		identityPrivs = append(identityPrivs, *credentialBasic.privateKey)
		credentials = append(credentials, credentialBasic)
		initPrivs = append(initPrivs, ikPriv)
		clientInitKeys[i] = *cik
		cik = nil
		//dump(clientInitKeys)
	}
	setupDone = true
}

func dump(ciks []ClientInitKey) {
	fmt.Println("---- DUMP -----")
	for _, cik := range ciks {
		fmt.Printf("priv %x pub %x\n", cik.privateKey.Data, cik.InitKey.Data)
	}
}

func TestState_TwoPerson(t *testing.T) {
	setup(t)
	// creator's state
	// dump(clientInitKeys)
	first0 := newEmptyState(groupId, suite, initPrivs[0], credentials[0])
	// add the second participant
	add := first0.add(clientInitKeys[1])
	_, err := first0.handle(add)
	assertNotError(t, err, "handle add failed")

	// commit adding the second participant
	secret, _ := getRandomBytes(32)
	_, welcome, first1, err := first0.commit(secret)
	assertNotError(t, err, "state_test. commit failed")

	// Initialize the second participant from the Welcome
	second0, err := newJoinedState([]ClientInitKey{clientInitKeys[1]}, *welcome)
	assertNotError(t, err, "state_test: state creation using Welcome failed")

	//assertByteEquals(t, *first1, *second0)

	/// Verify that they can exchange protected messages
	fmt.Printf(" >>>>>>>>> Protect/Unprotect <<<<<<<<< \n")
	ct, err := first1.protect(testMessage)
	assertNotError(t, err, "protect error")
	pt, err := second0.unprotect(ct)
	assertNotError(t, err, "unprotect failure")
	assertByteEquals(t, pt, testMessage)
}

func TestState_Multi(t *testing.T) {
	setup(t)
	// start with the group creator
	states = append(states, *newEmptyState(groupId, suite, initPrivs[0], credentials[0]))

	// add proposals for rest of the participants
	for i := 1; i < groupSize; i++ {
		add := states[0].add(clientInitKeys[i])
		_, err := states[0].handle(add)
		assertNotError(t, err, "add failed")
	}

	// commit the adds
	secret, _ := getRandomBytes(32)
	_, welcome, next, err := states[0].commit(secret)
	assertNotError(t, err, "commit add proposals failed")
	states[0] = *next
	// initialize the new joiners from the welcome
	for i := 1; i < groupSize; i++ {
		s, err := newJoinedState([]ClientInitKey{clientInitKeys[i]}, *welcome)
		assertNotError(t, err, "initializing the state from welcome failed")
		states = append(states, *s)
	}

	for i, s := range states {
		ct, _ := s.protect(testMessage)
		for j, o := range states {
			if i == j {
				continue
			}
			pt, _ := o.unprotect(ct)
			assertByteEquals(t, pt, testMessage)
		}
	}
}

func TestState_CipherNegotiation(t *testing.T) {
	// Alice supports P-256 and X25519
	alicePriv, _ := scheme.Generate()
	aliceBc := &BasicCredential{
		Identity:           []byte{0x01, 0x02, 0x03, 0x04},
		SignatureScheme:    scheme,
		SignaturePublicKey: alicePriv.PublicKey,
	}
	aliceCred := Credential{Basic: aliceBc, privateKey: &alicePriv}
	aliceSuites := []CipherSuite{P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM}
	var aliceCiks []ClientInitKey
	for _, s := range aliceSuites {
		cik, err := newClientInitKey(s, &aliceCred)
		assertNotError(t, err, "newClientInitKey error")
		aliceCiks = append(aliceCiks, *cik)
	}

	// Bob spuports P-256 and P-521
	bobPriv, _ := scheme.Generate()
	bobBc := &BasicCredential{
		Identity:           []byte{0x04, 0x05, 0x06, 0x07},
		SignatureScheme:    scheme,
		SignaturePublicKey: bobPriv.PublicKey,
	}
	bobCred := Credential{Basic: bobBc, privateKey: &bobPriv}
	bobSuites := []CipherSuite{P256_SHA256_AES128GCM, P521_SHA512_AES256GCM}
	var bobCiks []ClientInitKey
	for _, s := range bobSuites {
		cik, err := newClientInitKey(s, &bobCred)
		assertNotError(t, err, "newClientInitKey error")
		bobCiks = append(bobCiks, *cik)
	}

	// Bob should choose P-256
	secret, _ := getRandomBytes(32)
	welcome, bobState, err := negotiateWithPeer(groupId, bobCiks, aliceCiks, secret)
	assertNotError(t, err, "state negotiation failed")

	// Alice should also arrive at P-256
	aliceState, err := newJoinedState(aliceCiks, *welcome)
	assertNotError(t, err, "state negotiation failed")

	assertTrue(t, aliceState.Equals(*bobState), "states are unequal")

}
