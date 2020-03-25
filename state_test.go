package mls

import (
	"fmt"
	"testing"

	"github.com/bifurcation/mint/syntax"
	"github.com/stretchr/testify/require"
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
		require.Nil(t, err)
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
	states = append(states, *NewEmptyState(groupId, suite, stateTest.initPrivs[0], stateTest.credentials[0]))

	// add proposals for rest of the participants
	for i := 1; i < groupSize; i++ {
		add := states[0].Add(stateTest.clientInitKeys[i])
		_, err := states[0].Handle(add)
		require.Nil(t, err)
	}

	// commit the adds
	secret, _ := getRandomBytes(32)
	_, welcome, next, err := states[0].Commit(secret)
	require.Nil(t, err)
	states[0] = *next
	// initialize the new joiners from the welcome
	for i := 1; i < groupSize; i++ {
		s, err := NewJoinedState([]ClientInitKey{stateTest.clientInitKeys[i]}, *welcome)
		require.Nil(t, err)
		states = append(states, *s)
	}
	stateTest.states = states

	// Verify that the states are all equivalent
	for _, lhs := range stateTest.states {
		for _, rhs := range stateTest.states {
			require.True(t, lhs.Equals(rhs))
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
	first0 := NewEmptyState(groupId, suite, stateTest.initPrivs[0], stateTest.credentials[0])
	// add the second participant
	add := first0.Add(stateTest.clientInitKeys[1])
	_, err := first0.Handle(add)
	require.Nil(t, err)

	// commit adding the second participant
	secret, _ := getRandomBytes(32)
	_, welcome, first1, err := first0.Commit(secret)
	require.Nil(t, err)

	// Initialize the second participant from the Welcome
	second1, err := NewJoinedState([]ClientInitKey{stateTest.clientInitKeys[1]}, *welcome)
	require.Nil(t, err)

	// Verify that the two states are equivalent
	require.True(t, first1.Equals(*second1))

	/// Verify that they can exchange protected messages
	ct, err := first1.Protect(testMessage)
	require.Nil(t, err)
	pt, err := second1.Unprotect(ct)
	require.Nil(t, err)
	require.Equal(t, pt, testMessage)
}

func TestStateMarshalUnmarshal(t *testing.T) {
	// Create Alice and have her add Bob to a group
	stateTest := setup(t)
	alice0 := NewEmptyState(groupId, suite, stateTest.initPrivs[0], stateTest.credentials[0])

	add := alice0.Add(stateTest.clientInitKeys[1])
	_, err := alice0.Handle(add)
	require.Nil(t, err)

	secret, _ := getRandomBytes(32)
	_, welcome1, alice1, err := alice0.Commit(secret)
	require.Nil(t, err)

	// Marshal Alice's secret state
	alice1priv, err := syntax.Marshal(alice1.GetSecrets())
	require.Nil(t, err)

	// Initialize Bob generate an Update+Commit
	bob1, err := NewJoinedState([]ClientInitKey{stateTest.clientInitKeys[1]}, *welcome1)
	require.Nil(t, err)
	require.True(t, alice1.Equals(*bob1))

	update := bob1.Update(secret)
	_, err = bob1.Handle(update)
	require.Nil(t, err)

	commit, _, bob2, err := bob1.Commit(secret)
	require.Nil(t, err)

	// Recreate Alice from Welcome and secrets
	alice1aPriv := StateSecrets{}
	_, err = syntax.Unmarshal(alice1priv, &alice1aPriv)
	require.Nil(t, err)

	alice1a, err := NewStateFromWelcomeAndSecrets(*welcome1, alice1aPriv)
	require.Nil(t, err)

	// Verify that Alice can process Bob's Update+Commit
	_, err = alice1a.Handle(update)
	require.Nil(t, err)

	alice2, err := alice1a.Handle(commit)
	require.Nil(t, err)

	// Verify that Alice and Bob can exchange protected messages
	/// Verify that they can exchange protected messages
	ct, err := alice2.Protect(testMessage)
	require.Nil(t, err)
	pt, err := bob2.Unprotect(ct)
	require.Nil(t, err)
	require.Equal(t, pt, testMessage)
}

func TestStateMulti(t *testing.T) {
	stateTest := setup(t)
	// start with the group creator
	stateTest.states = append(stateTest.states, *NewEmptyState(groupId, suite, stateTest.initPrivs[0],
		stateTest.credentials[0]))

	// add proposals for rest of the participants
	for i := 1; i < groupSize; i++ {
		add := stateTest.states[0].Add(stateTest.clientInitKeys[i])
		_, err := stateTest.states[0].Handle(add)
		require.Nil(t, err)
	}

	// commit the adds
	secret, _ := getRandomBytes(32)
	_, welcome, next, err := stateTest.states[0].Commit(secret)
	require.Nil(t, err)
	stateTest.states[0] = *next
	// initialize the new joiners from the welcome
	for i := 1; i < groupSize; i++ {
		s, err := NewJoinedState([]ClientInitKey{stateTest.clientInitKeys[i]}, *welcome)
		require.Nil(t, err)
		stateTest.states = append(stateTest.states, *s)
	}

	// Verify that the states are all equivalent
	for _, lhs := range stateTest.states {
		for _, rhs := range stateTest.states {
			require.True(t, lhs.Equals(rhs))
		}
	}

	// verify that everyone can send and be received
	for i, s := range stateTest.states {
		ct, _ := s.Protect(testMessage)
		for j, o := range stateTest.states {
			if i == j {
				continue
			}
			pt, _ := o.Unprotect(ct)
			require.Equal(t, pt, testMessage)
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
		require.Nil(t, err)
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
		require.Nil(t, err)
		bobCiks = append(bobCiks, *cik)
	}

	// Bob should choose P-256
	secret, _ := getRandomBytes(32)
	welcome, bobState, err := negotiateWithPeer(groupId, bobCiks, aliceCiks, secret)
	require.Nil(t, err)

	// Alice should also arrive at P-256
	aliceState, err := NewJoinedState(aliceCiks, *welcome)
	require.Nil(t, err)

	require.True(t, aliceState.Equals(*bobState))
}

func TestStateUpdate(t *testing.T) {
	stateTest := setupGroup(t)
	for i, state := range stateTest.states {
		leafSecret, _ := getRandomBytes(32)
		update := state.Update(leafSecret)
		state.Handle(update)
		commit, _, next, err := state.Commit(leafSecret)
		require.Nil(t, err)

		for j, other := range stateTest.states {
			if j == i {
				stateTest.states[j] = *next
			} else {
				_, err := other.Handle(update)
				require.Nil(t, err)

				newState, err := other.Handle(commit)
				require.Nil(t, err)
				stateTest.states[j] = *newState
			}
		}

		for _, s := range stateTest.states {
			require.True(t, stateTest.states[0].Equals(s))
		}
	}
}

func TestStateRemove(t *testing.T) {
	stateTest := setupGroup(t)
	for i := groupSize - 2; i > 0; i-- {
		remove := stateTest.states[i].Remove(leafIndex(i + 1))
		stateTest.states[i].Handle(remove)
		secret, _ := getRandomBytes(32)
		commit, _, next, err := stateTest.states[i].Commit(secret)
		require.Nil(t, err)
		stateTest.states = stateTest.states[:len(stateTest.states)-1]

		for j, state := range stateTest.states {
			if j == i {
				stateTest.states[j] = *next
			} else {
				state.Handle(remove)
				newState, err := state.Handle(commit)
				require.Nil(t, err)
				stateTest.states[j] = *newState
			}
		}

		for _, s := range stateTest.states {
			require.True(t, s.Equals(stateTest.states[0]))
		}
	}
}
