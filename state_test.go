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

	testMessage = unhex("1112131415")
)

type StateTest struct {
	identityPrivs  []SignaturePrivateKey
	credentials    []Credential
	initPrivs      []HPKEPrivateKey
	clientInitKeys []ClientInitKey
	states         []State
}

func setup(t *testing.T) StateTest {
	stateTest := StateTest{}
	stateTest.clientInitKeys = make([]ClientInitKey, groupSize)

	for i := 0; i < groupSize; i++ {
		// cred gen
		sigPriv, _ := scheme.Generate()
		cred := NewBasicCredential(userId, scheme, &sigPriv)
		//cik gen
		cik, err := newClientInitKey(suite, cred)
		assertNotError(t, err, "newClientInitKey error")
		// save all the materials
		stateTest.identityPrivs = append(stateTest.identityPrivs, sigPriv)
		stateTest.credentials = append(stateTest.credentials, *cred)
		stateTest.initPrivs = append(stateTest.initPrivs, ikPriv)
		stateTest.clientInitKeys[i] = *cik
		cik = nil
		//dump(clientInitKeys)
	}
	return stateTest
}

func setupGroup(t *testing.T) StateTest {
	stateTest := setup(t)
	var states []State
	// start with the group creator
	states = append(states, *newEmptyState(groupId, suite, stateTest.initPrivs[0], stateTest.credentials[0]))

	// add proposals for rest of the participants
	for i := 1; i < groupSize; i++ {
		add := states[0].add(stateTest.clientInitKeys[i])
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
		s, err := newJoinedState([]ClientInitKey{stateTest.clientInitKeys[i]}, *welcome)
		assertNotError(t, err, "initializing the state from welcome failed")
		states = append(states, *s)
	}
	stateTest.states = states
	return stateTest
}

func dump(ciks []ClientInitKey) {
	fmt.Println("---- DUMP -----")
	for _, cik := range ciks {
		fmt.Printf("priv %x pub %x\n", cik.privateKey.Data, cik.InitKey.Data)
	}
}

func TestState_TwoPerson(t *testing.T) {
	stateTest := setup(t)
	// creator's state
	// dump(clientInitKeys)
	first0 := newEmptyState(groupId, suite, stateTest.initPrivs[0], stateTest.credentials[0])
	// add the second participant
	add := first0.add(stateTest.clientInitKeys[1])
	_, err := first0.handle(add)
	assertNotError(t, err, "handle add failed")

	// commit adding the second participant
	secret, _ := getRandomBytes(32)
	_, welcome, first1, err := first0.commit(secret)
	assertNotError(t, err, "state_test. commit failed")

	// Initialize the second participant from the Welcome
	second0, err := newJoinedState([]ClientInitKey{stateTest.clientInitKeys[1]}, *welcome)
	assertNotError(t, err, "state_test: state creation using Welcome failed")

	//assertByteEquals(t, *first1, *second0)

	/// Verify that they can exchange protected messages
	ct, err := first1.protect(testMessage)
	assertNotError(t, err, "protect error")
	pt, err := second0.unprotect(ct)
	assertNotError(t, err, "unprotect failure")
	assertByteEquals(t, pt, testMessage)
}

func TestState_Multi(t *testing.T) {
	stateTest := setup(t)
	// start with the group creator
	stateTest.states = append(stateTest.states, *newEmptyState(groupId, suite, stateTest.initPrivs[0],
		stateTest.credentials[0]))

	// add proposals for rest of the participants
	for i := 1; i < groupSize; i++ {
		add := stateTest.states[0].add(stateTest.clientInitKeys[i])
		_, err := stateTest.states[0].handle(add)
		assertNotError(t, err, "add failed")
	}

	// commit the adds
	secret, _ := getRandomBytes(32)
	_, welcome, next, err := stateTest.states[0].commit(secret)
	assertNotError(t, err, "commit add proposals failed")
	stateTest.states[0] = *next
	// initialize the new joiners from the welcome
	for i := 1; i < groupSize; i++ {
		s, err := newJoinedState([]ClientInitKey{stateTest.clientInitKeys[i]}, *welcome)
		assertNotError(t, err, "initializing the state from welcome failed")
		stateTest.states = append(stateTest.states, *s)
	}

	for i, s := range stateTest.states {
		ct, _ := s.protect(testMessage)
		for j, o := range stateTest.states {
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

func TestState_Update(t *testing.T) {
	stateTest := setupGroup(t)
	for i := 0; i < groupSize; i++ {
		leafSecret, _ := getRandomBytes(32)
		update := stateTest.states[i].update(leafSecret)
		stateTest.states[i].handle(update)
		commit, _, next, err := stateTest.states[i].commit(leafSecret)
		assertNotError(t, err, "creator commit error")
		for idx, state := range stateTest.states {
			if idx == i {
				state = *next
			} else {
				state.handle(update)
				newState, err := state.handle(commit)
				assertNotError(t, err, "new joinee commit fail")
				state = *newState
			}
		}

		for _, s := range stateTest.states {
			assertTrue(t, s.Equals(stateTest.states[0]), "states unequal")
		}
	}
}

func TestState_Remove(t *testing.T) {
	stateTest := setupGroup(t)
	for i := groupSize - 2; i > 0; i-- {
		remove := stateTest.states[i].remove(leafIndex(i + 1))
		stateTest.states[i].handle(remove)
		secret, _ := getRandomBytes(32)
		commit, _, next, err := stateTest.states[i].commit(secret)
		assertNotError(t, err, "remove error")
		stateTest.states = stateTest.states[:len(stateTest.states)-1]

		for idx, state := range stateTest.states {
			if idx == i {
				state = *next
			} else {
				state.handle(remove)
				newState, err := state.handle(commit)
				assertNotError(t, err, "remove processing error by others")
				state = *newState
			}
		}

		for _, s := range stateTest.states {
			assertTrue(t, s.Equals(stateTest.states[0]), "states unequal")
		}
	}
}
