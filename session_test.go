package mls

import (
	"math/rand"
	"testing"
)

const noExcept int = 0xffffffff

//
//SessionTest type definition
//
type SessionTest struct {
	CipherSuite CipherSuite
	Scheme      SignatureScheme
	GroupSize   int
	SecretSize  int
	numSessions int
	GroupID     []byte `tls:"head=1"`
	UserID      []byte `tls:"head=1"`
	Sessions    []Session
	testing     *testing.T

	identityPrivs  []SignaturePrivateKey
	credentials    []Credential
	initPrivs      []HPKEPrivateKey
	clientInitKeys []ClientInitKey
	states         []State
}

func setupSessionTest(t *testing.T) *SessionTest {
	sessionTest := SessionTest{}

	sessionTest.CipherSuite = P256_SHA256_AES128GCM
	sessionTest.Scheme = Ed25519
	sessionTest.GroupSize = 5
	sessionTest.SecretSize = 32
	sessionTest.GroupID = []byte{0x01, 0x02, 0x03, 0x04}
	sessionTest.UserID = []byte{0x04, 0x05, 0x06, 0x07}
	sessionTest.numSessions = 1
	sessionTest.testing = t

	return &sessionTest

}
func (s *SessionTest) newIdentityKey() (SignaturePrivateKey, error) {

	return s.Scheme.Generate()
}

func (s *SessionTest) freshSecret() ([]byte, error) {
	freshVal := make([]byte, s.SecretSize)
	rand.Read(freshVal)
	return freshVal, nil
}

func (s *SessionTest) broadcast(message []byte, except int) {

	initEpoch := s.Sessions[0].CurrentEpoch

	for _, sess := range s.Sessions {
		if except != noExcept && sess.currentState().Index == leafIndex(except) {

			continue
		}

		sess.handle(message)
	}
	s.check(initEpoch, except)
}

func (s *SessionTest) broadcastAdd(from int, index int) {

	//initSecret, err1 := s.freshSecret()
	//assertNotError(s.testing, err1, "initSecret error")

	idPriv, err2 := s.newIdentityKey()
	assertNotError(s.testing, err2, "New ID KEY error")
	cred := NewBasicCredential(s.UserID, s.Scheme, &idPriv)
	initKey, err := NewClientInitKey(s.CipherSuite, cred)
	assertNotError(s.testing, err, "NewClientInitKey error")
	initKeys := []ClientInitKey{*initKey}

	if len(s.Sessions) == 0 {
		//myInitSecret, err3 := s.freshSecret()
		myIDPriv, err4 := s.newIdentityKey()
		assertNotError(s.testing, err4, "New ID KEY error")

		myCred := NewBasicCredential(s.UserID, s.Scheme, &myIDPriv)
		myInitKey, err := NewClientInitKey(s.CipherSuite, myCred)
		assertNotError(s.testing, err, "NewClientInitKey error")

		commitSecret, err := s.freshSecret()
		creator, welcome, err := startSession(s.GroupID, []ClientInitKey{*myInitKey}, initKeys, commitSecret)
		assertNotError(s.testing, err, "Error starting session")

		joiner, err := joinSession(initKeys, *welcome)
		assertNotError(s.testing, err, "Error joining session")

		s.Sessions = append(s.Sessions, *creator)
		s.Sessions = append(s.Sessions, *joiner)
		return

	}

	//initEpoch := s.Sessions[0].CurrentEpoch
	addSecret, err := s.freshSecret()
	welcome, add := s.Sessions[from].add(addSecret, *initKey)
	assertNotError(s.testing, err, "Error adding participant")

	next, err := joinSession(initKeys, *welcome)
	assertNotError(s.testing, err, "Error joining new participant")

	s.broadcast(add, index)

	if index == len(s.Sessions) {
		s.Sessions = append(s.Sessions, *next)
	} else if index < len(s.Sessions) {

		s.Sessions[index] = *next
	} else {

		s.testing.Fatalf("Index too large for group")
	}

}

func setupSession(t *testing.T) *SessionTest {
	sessionTest := SessionTest{}

	sessionTest.CipherSuite = P256_SHA256_AES128GCM
	sessionTest.Scheme = Ed25519
	sessionTest.GroupSize = 5
	sessionTest.SecretSize = 32
	sessionTest.GroupID = []byte{0x01, 0x02, 0x03, 0x04}
	sessionTest.UserID = []byte{0x04, 0x05, 0x06, 0x07}
	sessionTest.numSessions = 1
	sessionTest.testing = t

	return &sessionTest

}

func (s *SessionTest) check(initEpoch Epoch, except int) {

	ref := 0

	if except == 0 && len(s.Sessions) > 1 {

		ref = 1
	}

	for _, sess := range s.Sessions {

		if except != noExcept && sess.currentState().Index == leafIndex(except) {

			continue
		}

		assertEquals(s.testing, sess.evaluateEquals(s.Sessions[ref]), true)

		pt := []byte{0, 1, 2, 3}
		ct := sess.protect(pt)

		for _, otherSess := range s.Sessions {

			if except != noExcept && sess.currentState().Index == leafIndex(except) {

				continue
			}

			decryptedPT := otherSess.unprotect(ct)
			assertEquals(s.testing, pt, decryptedPT)
		}

		assertTrue(s.testing, !(s.Sessions[ref].CurrentEpoch == initEpoch), "Differnt Epochs")

	}

}

func TestExecTwoPeopleTest(t *testing.T) {

	test := setupSessionTest(t)
	size := len(test.Sessions)
	test.broadcastAdd(size-1, size)
}

func TestExecFullGroupTest(t *testing.T) {
	test := setupSessionTest(t)

	for len(test.Sessions) < test.GroupSize {

		size := len(test.Sessions)
		test.broadcastAdd(size-1, size)
		//fmt.Println("This ran")

	}

}

func TestExecCyphersuiteNegotiationTest(t *testing.T) {
	test := setupSessionTest(t)

	//Code creates keys that support P-256 and X25519 for alice
	aliceIDKey, err := test.newIdentityKey()
	assertNotError(test.testing, err, "New ID KEY error")

	aliceCred := NewBasicCredential(test.UserID, test.Scheme, &aliceIDKey)

	aliceCiphers := []CipherSuite{P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM}

	var aliceCIKs []ClientInitKey

	for _, suiteA := range aliceCiphers {

		initKey, err := NewClientInitKey(suiteA, aliceCred)
		assertNotError(test.testing, err, "New ID KEY error")

		aliceCIKs = append(aliceCIKs, *initKey)
	}

	//Code creates keys that support P-256 and X25519 for bob
	bobIDKey, err := test.newIdentityKey()
	assertNotError(test.testing, err, "New Init KEY error")

	bobCred := NewBasicCredential(test.UserID, test.Scheme, &bobIDKey)

	bobCiphers := []CipherSuite{P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM}

	var bobCIKs []ClientInitKey

	for _, suiteB := range bobCiphers {

		initKey, err := NewClientInitKey(suiteB, bobCred)
		assertNotError(test.testing, err, "New Init KEY error")

		bobCIKs = append(bobCIKs, *initKey)
	}

	initSecret, err := test.freshSecret()
	assertNotError(test.testing, err, "Fresh secret error")

	alice, welcome, err := startSession([]byte{0x01, 0x02, 0x03, 0x04}, aliceCIKs, bobCIKs, initSecret)
	assertNotError(test.testing, err, "Error starting session")

	bob, err := joinSession(bobCIKs, *welcome)
	assertNotError(test.testing, err, "Error joining session")

	//assertEquals(test.testing, alice, bob)

	if alice.evaluateEquals(*bob) != false {

		test.testing.Fatalf("The are diffent")
	}

}

func TestExecUpdateTest(t *testing.T) {

	//Initialize the group
	test := setupSessionTest(t)

	for len(test.Sessions) < test.GroupSize {

		size := len(test.Sessions)
		test.broadcastAdd(size-1, size)

	}

	//Have the whole group update
	for i := 0; i < test.GroupSize; i++ {

		initEpoch := test.Sessions[0].CurrentEpoch
		updateSecret, err := test.freshSecret()
		assertNotError(test.testing, err, "Fresh secret error")

		update := test.Sessions[i].update(updateSecret)
		test.broadcast(update, noExcept)
		test.check(initEpoch, noExcept)

	}

}

func TestExecRemoveTest(t *testing.T) {

	//Initialize the group
	test := setupSessionTest(t)

	for len(test.Sessions) < test.GroupSize {

		size := len(test.Sessions)
		test.broadcastAdd(size-1, size)

	}

	//Remove all members of the group but creator
	for i := (test.GroupSize - 1); i > 0; i-- {

		initEpoch := test.Sessions[0].CurrentEpoch
		evictSecret, err := test.freshSecret()
		assertNotError(test.testing, err, "Fresh secret error")

		remove := test.Sessions[i-1].remove(evictSecret, uint32(i))
		test.Sessions = test.Sessions[:len(test.Sessions)-1]

		test.broadcast(remove, noExcept)
		test.check(initEpoch, noExcept)

	}

}

func TestExecReplaceTest(t *testing.T) {

	//Initialize the group
	test := setupSessionTest(t)

	for len(test.Sessions) < test.GroupSize {

		size := len(test.Sessions)
		test.broadcastAdd(size-1, size)
	}

	//Conduct replacement of some group members
	for i := 0; i > test.GroupSize; i++ {
		target := (i + 1) % test.GroupSize

		//remove target
		initEpoch := test.Sessions[i].CurrentEpoch
		evictSecret, err := test.freshSecret()
		assertNotError(test.testing, err, "Fresh secret error")

		remove := test.Sessions[i].remove(evictSecret, uint32(target))
		test.broadcast(remove, target)
		test.check(initEpoch, target)

		//re-add at target
		initEpoch = test.Sessions[i].CurrentEpoch
		test.broadcastAdd(i, target)

	}
}

func TestExecFullLifeCycleTest(t *testing.T) {

	//initialize the group
	test := setupSessionTest(t)

	for len(test.Sessions) < test.GroupSize {

		size := len(test.Sessions)
		test.broadcastAdd(size-1, size)
	}

	//Execute an update for everyone
	for i := 0; i < (test.GroupSize - 1); i++ {

		initEpoch := test.Sessions[0].CurrentEpoch
		updateSecret, err := test.freshSecret()
		assertNotError(test.testing, err, "Fresh secret error")

		update := test.Sessions[i].update(updateSecret)
		test.broadcast(update, noExcept)
		test.check(initEpoch, noExcept)

	}

	//Remove all members of the group but creator
	for i := (test.GroupSize - 1); i > 0; i-- {

		initEpoch := test.Sessions[0].CurrentEpoch
		evictSecret, err := test.freshSecret()
		assertNotError(test.testing, err, "Fresh secret error")

		remove := test.Sessions[i-1].remove(evictSecret, uint32(i))
		test.Sessions = test.Sessions[:len(test.Sessions)-1]

		test.broadcast(remove, noExcept)
		test.check(initEpoch, noExcept)

	}

}
