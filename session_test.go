package mls

import (
	"crypto/rand"
	"testing"
)

const (
	noExcept = 0xffffffff
)

type SessionTest struct {
	T         *testing.T
	Suite     CipherSuite
	Scheme    SignatureScheme
	GroupSize int
	GroupID   []byte
	UserID    []byte
	Sessions  []*Session
}

func NewSessionTest(t *testing.T) *SessionTest {
	return &SessionTest{
		T:         t,
		Suite:     P256_SHA256_AES128GCM,
		Scheme:    Ed25519,
		GroupSize: 5,
		GroupID:   []byte{0, 1, 2, 3},
		UserID:    []byte{4, 5, 6, 7},
	}
}

func (st SessionTest) NewIdentityKey() SignaturePrivateKey {
	priv, err := st.Scheme.Generate()
	assertNotError(st.T, err, "Error generating signature key")
	return priv
}

func (st SessionTest) FreshSecret() []byte {
	secret := make([]byte, st.Suite.constants().SecretSize)
	rand.Read(secret)
	return secret
}

func (st *SessionTest) Broadcast(message []byte, except int) {
	initialEpoch := st.Sessions[0].CurrentEpoch
	for _, session := range st.Sessions {
		if except != noExcept && session.Index() == leafIndex(except) {
			continue
		}

		err := session.Handle(message)
		assertNotError(st.T, err, "Error processing message")
	}
	st.Check(initialEpoch, except)
}

func (st *SessionTest) BroadcastAdd(from, index int) {
	idPriv := st.NewIdentityKey()
	cred := newBasicCredential(st.Scheme, st.UserID, &idPriv)

	clientInitKey, err := newClientInitKey(st.Suite, cred)
	clientInitKeys := []ClientInitKey{*clientInitKey}
	assertNotError(st.T, err, "Error constructing init key")

	// Initial add is different
	if len(st.Sessions) == 0 {
		myIDPriv := st.NewIdentityKey()
		myCred := newBasicCredential(st.Scheme, st.UserID, &myIDPriv)

		myCIK, err := newClientInitKey(st.Suite, myCred)
		myCIKs := []ClientInitKey{*myCIK}
		assertNotError(st.T, err, "Error constructing init key")

		commitSecret := st.FreshSecret()
		creator, welcome, err := StartSession(st.GroupID, myCIKs, clientInitKeys, commitSecret)
		assertNotError(st.T, err, "Error starting session")

		joiner, err := JoinSession(clientInitKeys, *welcome)
		assertNotError(st.T, err, "Error joining session")

		st.Sessions = append(st.Sessions, creator)
		st.Sessions = append(st.Sessions, joiner)
		return
	}

	initialEpoch := st.Sessions[0].CurrentEpoch

	addSecret := st.FreshSecret()
	welcome, add, err := st.Sessions[from].Add(addSecret, *clientInitKey)
	assertNotError(st.T, err, "Error adding new member")

	next, err := JoinSession(clientInitKeys, *welcome)
	assertNotError(st.T, err, "Error joining session")

	st.Broadcast(add, index)

	// Add-in-place vs. add-at-edge
	switch {
	case index == len(st.Sessions):
		st.Sessions = append(st.Sessions, next)
	case index < len(st.Sessions):
		st.Sessions[index] = next
	default:
		st.T.Fatalf("Index too large for group")
	}

	st.Check(initialEpoch, noExcept)
}

func (st *SessionTest) Check(initialEpoch Epoch, except int) {
	ref := 0
	if except == 0 && len(st.Sessions) > 1 {
		ref = 1
	}

	for _, session := range st.Sessions {
		if except != noExcept && session.Index() == leafIndex(except) {
			continue
		}

		assertTrue(st.T, session.Equals(st.Sessions[ref]), "Session mismatch")

		plaintext := []byte{0, 1, 2, 3}
		encrypted, err := session.Protect(plaintext)
		assertNotError(st.T, err, "Error in protect")

		for _, other := range st.Sessions {
			if except != noExcept && other.Index() == leafIndex(except) {
				continue
			}

			decrypted, err := other.Unprotect(encrypted)
			assertNotError(st.T, err, "Error in unprotect")
			assertByteEquals(st.T, plaintext, decrypted)
		}
	}
}

func TestCreateTwoPersonSession(t *testing.T) {
	st := NewSessionTest(t)
	st.BroadcastAdd(-1, 0)
}

func TestCreateFullSizeSession(t *testing.T) {
	st := NewSessionTest(t)
	for len(st.Sessions) < st.GroupSize {
		size := len(st.Sessions)
		st.BroadcastAdd(size-1, size)
	}
}
