package mls

import (
	"testing"

	"github.com/cisco/go-tls-syntax"
	"github.com/stretchr/testify/require"
)

var (
	groupID   = []byte{0x01, 0x02, 0x03, 0x04}
	userID    = []byte{0x04, 0x05, 0x06, 0x07}
	suite     = P256_AES128GCM_SHA256_P256
	groupSize = 5

	testMessage = unhex("1112131415")
)

type StateTest struct {
	initSecrets   [][]byte
	identityPrivs []SignaturePrivateKey
	credentials   []Credential
	initPrivs     []HPKEPrivateKey
	keyPackages   []KeyPackage
	states        []State
}

func setup(t *testing.T) StateTest {
	stateTest := StateTest{}
	stateTest.keyPackages = make([]KeyPackage, groupSize)
	scheme := suite.Scheme()

	for i := 0; i < groupSize; i++ {
		// cred gen
		secret := randomBytes(32)
		sigPriv, err := scheme.Derive(secret)
		require.Nil(t, err)

		cred := NewBasicCredential(userID, scheme, &sigPriv)

		//kp gen
		initKey, err := suite.hpke().Derive(secret)
		require.Nil(t, err)

		kp, err := NewKeyPackageWithInitKey(suite, initKey, cred)
		require.Nil(t, err)

		// save all the materials
		stateTest.initSecrets = append(stateTest.initSecrets, secret)
		stateTest.identityPrivs = append(stateTest.identityPrivs, sigPriv)
		stateTest.credentials = append(stateTest.credentials, *cred)
		stateTest.initPrivs = append(stateTest.initPrivs, *kp.privateKey)
		stateTest.keyPackages[i] = *kp
		stateTest.keyPackages[i].RemovePrivateKey()
	}
	return stateTest
}

func setupGroup(t *testing.T) StateTest {
	stateTest := setup(t)
	var states []State
	// start with the group creator
	err := stateTest.keyPackages[0].SetPrivateKey(stateTest.initPrivs[0])
	require.Nil(t, err)
	s0, err := NewEmptyState(groupID, stateTest.initSecrets[0], stateTest.keyPackages[0])
	require.Nil(t, err)
	states = append(states, *s0)

	// add proposals for rest of the participants
	for i := 1; i < groupSize; i++ {
		add, err := states[0].Add(stateTest.keyPackages[i])
		require.Nil(t, err)
		_, err = states[0].Handle(add)
		require.Nil(t, err)
	}

	// commit the adds
	secret := randomBytes(32)
	_, welcome, next, err := states[0].Commit(secret)
	require.Nil(t, err)
	states[0] = *next
	// initialize the new joiners from the welcome
	for i := 1; i < groupSize; i++ {
		err = stateTest.keyPackages[i].SetPrivateKey(stateTest.initPrivs[i])
		require.Nil(t, err)
		s, err := NewJoinedState(stateTest.initSecrets[i], []KeyPackage{stateTest.keyPackages[i]}, *welcome)
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

func TestStateTwoPerson(t *testing.T) {
	stateTest := setup(t)
	// creator's state
	err := stateTest.keyPackages[0].SetPrivateKey(stateTest.initPrivs[0])
	require.Nil(t, err)
	first0, err := NewEmptyState(groupID, stateTest.initSecrets[0], stateTest.keyPackages[0])
	require.Nil(t, err)

	// add the second participant
	add, err := first0.Add(stateTest.keyPackages[1])
	require.Nil(t, err)
	_, err = first0.Handle(add)
	require.Nil(t, err)

	// commit adding the second participant
	secret := randomBytes(32)
	_, welcome, first1, err := first0.Commit(secret)
	require.Nil(t, err)
	require.Equal(t, first1.NewCredentials, map[LeafIndex]bool{1: true})

	// Initialize the second participant from the Welcome
	err = stateTest.keyPackages[1].SetPrivateKey(stateTest.initPrivs[1])
	require.Nil(t, err)
	second1, err := NewJoinedState(stateTest.initSecrets[1], []KeyPackage{stateTest.keyPackages[1]}, *welcome)
	require.Nil(t, err)
	require.Equal(t, second1.NewCredentials, map[LeafIndex]bool{0: true, 1: true})

	// Verify that the two states are equivalent
	require.True(t, first1.Equals(*second1))

	/// Verify that they can exchange protected messages
	ct, err := first1.Protect(testMessage)
	require.Nil(t, err)
	pt, err := second1.Unprotect(ct)
	require.Nil(t, err)
	require.Equal(t, pt, testMessage)
}

const ExtensionTypeGroupTest ExtensionType = 0xFFFF

type GroupTestExtension struct{}

func (gte GroupTestExtension) Type() ExtensionType {
	return ExtensionTypeGroupTest
}

func TestStateExtensions(t *testing.T) {
	stateTest := setup(t)
	groupExtensions := NewExtensionList()
	groupExtensions.Add(GroupTestExtension{})

	clientExtensions := []ExtensionBody{GroupTestExtension{}}

	// Check that NewEmptyStateWithExtensions fails if the KP doesn't support them
	kpA := stateTest.keyPackages[0]
	err := kpA.SetPrivateKey(stateTest.initPrivs[0])
	require.Nil(t, err)
	_, err = NewEmptyStateWithExtensions(groupID, stateTest.initSecrets[0], kpA, groupExtensions)
	require.Error(t, err)

	// Check that NewEmptyStateWithExtensions succeeds with exetnsion support
	err = kpA.SetExtensions(clientExtensions)
	require.Nil(t, err)
	err = kpA.Sign(stateTest.identityPrivs[0])
	require.Nil(t, err)

	alice0, err := NewEmptyStateWithExtensions(groupID, stateTest.initSecrets[0], kpA, groupExtensions)
	require.Nil(t, err)
	require.Equal(t, len(alice0.Extensions.Entries), 1)

	// Check that Add fails if the KP doesn't support them
	kpB := stateTest.keyPackages[1]
	_, err = alice0.Add(kpB)
	require.Error(t, err)

	// Check that Add succeeds with extension support
	err = kpB.SetExtensions(clientExtensions)
	require.Nil(t, err)
	err = kpB.Sign(stateTest.identityPrivs[1])
	require.Nil(t, err)

	_, err = alice0.Add(kpB)
	require.Nil(t, err)

	// TODO(RLB) Test extension verificatoin in NewJoinedState
}

func TestStateMarshalUnmarshal(t *testing.T) {
	// Create Alice and have her add Bob to a group
	stateTest := setup(t)
	err := stateTest.keyPackages[0].SetPrivateKey(stateTest.initPrivs[0])
	require.Nil(t, err)
	alice0, err := NewEmptyState(groupID, stateTest.initSecrets[0], stateTest.keyPackages[0])
	require.Nil(t, err)

	add, err := alice0.Add(stateTest.keyPackages[1])
	require.Nil(t, err)
	_, err = alice0.Handle(add)
	require.Nil(t, err)

	secret := randomBytes(32)
	_, welcome1, alice1, err := alice0.Commit(secret)
	require.Nil(t, err)

	// Marshal Alice's secret state
	alice1priv, err := syntax.Marshal(alice1.GetSecrets())
	require.Nil(t, err)

	// Initialize Bob generate an Update+Commit
	err = stateTest.keyPackages[1].SetPrivateKey(stateTest.initPrivs[1])
	require.Nil(t, err)
	bob1, err := NewJoinedState(stateTest.initSecrets[1], []KeyPackage{stateTest.keyPackages[1]}, *welcome1)
	require.Nil(t, err)
	require.True(t, alice1.Equals(*bob1))

	newSecret := randomBytes(32)
	newInitKey, err := suite.hpke().Derive(newSecret)
	require.Nil(t, err)
	newKP, err := NewKeyPackageWithInitKey(suite, newInitKey, &stateTest.keyPackages[1].Credential)
	require.Nil(t, err)
	update, err := bob1.Update(newSecret, *newKP)
	require.Nil(t, err)
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

	require.True(t, alice1a.TreePriv.ConsistentPub(alice1.Tree))
	require.True(t, alice1.TreePriv.ConsistentPub(alice1a.Tree))

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
	err := stateTest.keyPackages[0].SetPrivateKey(stateTest.initPrivs[0])
	require.Nil(t, err)
	s0, err := NewEmptyState(groupID, stateTest.initSecrets[0], stateTest.keyPackages[0])
	require.Nil(t, err)
	stateTest.states = append(stateTest.states, *s0)

	// add proposals for rest of the participants
	for i := 1; i < groupSize; i++ {
		add, err := stateTest.states[0].Add(stateTest.keyPackages[i])
		require.Nil(t, err)
		_, err = stateTest.states[0].Handle(add)
		require.Nil(t, err)
	}

	// commit the adds
	secret := randomBytes(32)
	_, welcome, next, err := stateTest.states[0].Commit(secret)
	require.Nil(t, err)
	stateTest.states[0] = *next
	// initialize the new joiners from the welcome
	for i := 1; i < groupSize; i++ {
		err = stateTest.keyPackages[i].SetPrivateKey(stateTest.initPrivs[i])
		require.Nil(t, err)
		s, err := NewJoinedState(stateTest.initSecrets[i], []KeyPackage{stateTest.keyPackages[i]}, *welcome)
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
	scheme := suite.Scheme()
	aliceSecret := randomBytes(32)
	alicePriv, _ := scheme.Generate()
	aliceBc := &BasicCredential{
		Identity:           []byte{0x01, 0x02, 0x03, 0x04},
		SignatureScheme:    scheme,
		SignaturePublicKey: alicePriv.PublicKey,
	}
	aliceCred := Credential{Basic: aliceBc, privateKey: &alicePriv}
	aliceSuites := []CipherSuite{P256_AES128GCM_SHA256_P256, X25519_AES128GCM_SHA256_Ed25519}
	var aliceKPs []KeyPackage
	for _, s := range aliceSuites {
		initKey, err := suite.hpke().Derive(aliceSecret)
		require.Nil(t, err)

		kp, err := NewKeyPackageWithInitKey(s, initKey, &aliceCred)
		require.Nil(t, err)
		aliceKPs = append(aliceKPs, *kp)
	}

	// Bob spuports P-256 and P-521
	bobSecret := randomBytes(32)
	bobPriv, _ := scheme.Generate()
	bobBc := &BasicCredential{
		Identity:           []byte{0x04, 0x05, 0x06, 0x07},
		SignatureScheme:    scheme,
		SignaturePublicKey: bobPriv.PublicKey,
	}
	bobCred := Credential{Basic: bobBc, privateKey: &bobPriv}
	bobSuites := []CipherSuite{P256_AES128GCM_SHA256_P256, X25519_AES128GCM_SHA256_Ed25519}
	var bobKPs []KeyPackage
	for _, s := range bobSuites {
		initKey, err := suite.hpke().Derive(aliceSecret)
		require.Nil(t, err)

		kp, err := NewKeyPackageWithInitKey(s, initKey, &bobCred)
		require.Nil(t, err)
		bobKPs = append(bobKPs, *kp)
	}

	// Bob should choose P-256
	secret := randomBytes(32)
	welcome, bobState, err := negotiateWithPeer(groupID, bobSecret, bobKPs, aliceKPs, secret)
	require.Nil(t, err)

	// Alice should also arrive at P-256
	aliceState, err := NewJoinedState(aliceSecret, aliceKPs, *welcome)
	require.Nil(t, err)

	require.True(t, aliceState.Equals(*bobState))
}

func TestStateUpdate(t *testing.T) {
	stateTest := setupGroup(t)
	for i, state := range stateTest.states {
		oldCred := stateTest.keyPackages[i].Credential
		/* TODO(RLB): Re-enable changing credential public key
		newPriv, _ := oldCred.Scheme().Generate()
		newCred := NewBasicCredential(oldCred.Identity(), oldCred.Scheme(), &newPriv)
		*/
		newIdentity := append(oldCred.Identity(), []byte("-new")...)
		newCred := NewBasicCredential(newIdentity, oldCred.Scheme(), &state.IdentityPriv)

		newSecret := randomBytes(32)
		newInitKey, err := suite.hpke().Derive(newSecret)
		require.Nil(t, err)

		newKP, err := NewKeyPackageWithInitKey(suite, newInitKey, newCred)
		require.Nil(t, err)

		update, err := state.Update(newSecret, *newKP)
		require.Nil(t, err)
		state.Handle(update)

		commitSecret := randomBytes(32)
		commit, _, next, err := state.Commit(commitSecret)
		require.Nil(t, err)

		for j := range stateTest.states {
			if j == i {
				stateTest.states[j] = *next
			} else {
				_, err := stateTest.states[j].Handle(update)
				require.Nil(t, err)

				newState, err := stateTest.states[j].Handle(commit)
				require.Nil(t, err)
				stateTest.states[j] = *newState
			}

			require.Equal(t, stateTest.states[j].NewCredentials, map[LeafIndex]bool{LeafIndex(i): true})
			require.True(t, stateTest.states[0].Equals(stateTest.states[j]))
		}
	}
}

func TestStateRemove(t *testing.T) {
	stateTest := setupGroup(t)
	for i := groupSize - 2; i > 0; i-- {
		remove, err := stateTest.states[i].Remove(LeafIndex(i + 1))
		require.Nil(t, err)
		stateTest.states[i].Handle(remove)
		secret := randomBytes(32)
		commit, _, next, err := stateTest.states[i].Commit(secret)
		require.Nil(t, err)

		stateTest.states = stateTest.states[:len(stateTest.states)-1]

		for j := range stateTest.states {
			if j == i {
				stateTest.states[j] = *next
			} else {
				_, err := stateTest.states[j].Handle(remove)
				require.Nil(t, err)

				newState, err := stateTest.states[j].Handle(commit)
				require.Nil(t, err)
				stateTest.states[j] = *newState
			}

			require.True(t, stateTest.states[0].Equals(stateTest.states[j]))
		}
	}
}
