package mls

import (
	"fmt"
	"testing"

	"github.com/bifurcation/mint/syntax"
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
		cik, err := NewClientInitKey(suite, cred)
		assertNotError(t, err, "NewClientInitKey error")
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

	// Verify that the states are all equivalent
	for _, lhs := range stateTest.states {
		for _, rhs := range stateTest.states {
			assertTrue(t, lhs.Equals(rhs), "State mismatch")
		}
	}

	return stateTest
}

func dump(ciks []ClientInitKey) {
	fmt.Println("---- DUMP -----")
	for _, cik := range ciks {
		fmt.Printf("priv %x pub %x\n", cik.privateKey.Data, cik.InitKey.Data)
	}
}

func TestStateTwoPerson(t *testing.T) {
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
	second1, err := newJoinedState([]ClientInitKey{stateTest.clientInitKeys[1]}, *welcome)
	assertNotError(t, err, "state_test: state creation using Welcome failed")

	// Verify that the two states are equivalent
	assertTrue(t, first1.Equals(*second1), "State mismatch")

	/// Verify that they can exchange protected messages
	ct, err := first1.protect(testMessage)
	assertNotError(t, err, "protect error")
	pt, err := second1.unprotect(ct)
	assertNotError(t, err, "unprotect failure")
	assertByteEquals(t, pt, testMessage)
}

func TestStateMarshalUnmarshal(t *testing.T) {
	// Create Alice and have her add Bob to a group
	stateTest := setup(t)
	alice0 := newEmptyState(groupId, suite, stateTest.initPrivs[0], stateTest.credentials[0])

	add := alice0.add(stateTest.clientInitKeys[1])
	_, err := alice0.handle(add)
	assertNotError(t, err, "Initial add failed")

	secret, _ := getRandomBytes(32)
	_, welcome1, alice1, err := alice0.commit(secret)
	assertNotError(t, err, "Initial commit failed")

	// Marshal Alice's secret state
	alice1priv, err := syntax.Marshal(alice1.GetSecrets())
	assertNotError(t, err, "Error marshaling Alice private values")

	// Initialize Bob generate an Update+Commit
	bob1, err := newJoinedState([]ClientInitKey{stateTest.clientInitKeys[1]}, *welcome1)
	assertNotError(t, err, "state_test: state creation using Welcome failed")
	assertTrue(t, alice1.Equals(*bob1), "State mismatch")

	update := bob1.update(secret)
	_, err = bob1.handle(update)
	assertNotError(t, err, "Update failed at Bob")

	commit, _, bob2, err := bob1.commit(secret)
	assertNotError(t, err, "Update commit generation failed")

	// Recreate Alice from Welcome and secrets
	alice1aPriv := StateSecrets{}
	_, err = syntax.Unmarshal(alice1priv, &alice1aPriv)
	assertNotError(t, err, "Error unmarshaling Alice private values")

	alice1a, err := newStateFromWelcomeAndSecrets(*welcome1, alice1aPriv)
	assertNotError(t, err, "Error importing group info from Welcome")

	// Verify that Alice can process Bob's Update+Commit
	_, err = alice1a.handle(update)
	assertNotError(t, err, "Update failed at Alice")

	alice2, err := alice1a.handle(commit)
	assertNotError(t, err, "Update commit handling failed")

	// Verify that Alice and Bob can exchange protected messages
	/// Verify that they can exchange protected messages
	ct, err := alice2.protect(testMessage)
	assertNotError(t, err, "protect error")
	pt, err := bob2.unprotect(ct)
	assertNotError(t, err, "unprotect failure")
	assertByteEquals(t, pt, testMessage)
}

func TestStateMulti(t *testing.T) {
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

	// Verify that the states are all equivalent
	for _, lhs := range stateTest.states {
		for _, rhs := range stateTest.states {
			assertTrue(t, lhs.Equals(rhs), "State mismatch")
		}
	}

	// verify that everyone can send and be received
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

func TestStateCipherNegotiation(t *testing.T) {
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
		cik, err := NewClientInitKey(s, &aliceCred)
		assertNotError(t, err, "NewClientInitKey error")
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
		cik, err := NewClientInitKey(s, &bobCred)
		assertNotError(t, err, "NewClientInitKey error")
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

func TestStateUpdate(t *testing.T) {
	stateTest := setupGroup(t)
	for i, state := range stateTest.states {
		leafSecret, _ := getRandomBytes(32)
		update := state.update(leafSecret)
		state.handle(update)
		commit, _, next, err := state.commit(leafSecret)
		assertNotError(t, err, "creator commit error")

		for j, other := range stateTest.states {
			if j == i {
				stateTest.states[j] = *next
			} else {
				_, err := other.handle(update)
				assertNotError(t, err, "Update recipient proposal fail")

				newState, err := other.handle(commit)
				assertNotError(t, err, "Update recipient commit fail")
				stateTest.states[j] = *newState
			}
		}

		for _, s := range stateTest.states {
			assertTrue(t, stateTest.states[0].Equals(s), "states unequal")
		}
	}
}

func TestStateRemove(t *testing.T) {
	stateTest := setupGroup(t)
	for i := groupSize - 2; i > 0; i-- {
		remove := stateTest.states[i].remove(leafIndex(i + 1))
		stateTest.states[i].handle(remove)
		secret, _ := getRandomBytes(32)
		commit, _, next, err := stateTest.states[i].commit(secret)
		assertNotError(t, err, "remove error")
		stateTest.states = stateTest.states[:len(stateTest.states)-1]

		for j, state := range stateTest.states {
			if j == i {
				stateTest.states[j] = *next
			} else {
				state.handle(remove)
				newState, err := state.handle(commit)
				assertNotError(t, err, "remove processing error by others")
				stateTest.states[j] = *newState
			}
		}

		for _, s := range stateTest.states {
			assertTrue(t, s.Equals(stateTest.states[0]), "states unequal")
		}
	}
}
