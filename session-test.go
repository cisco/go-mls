package mls

import "testing"

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

func newIdentityKey() (SignaturePrivateKey, error) {

	return scheme.Generate()
}

func freshSecret() ([]byte, error) {

	return getRandomBytes(secretSize)
}

func broadcast(message []bytes) {

	broadcast(message, noExcept)
}

func (s *SessionTest) broadcast(message []bytes, except int) {

	initEpoch := s.Sessions[0].CurrentEpoch

	for i, sess := range s.Sessions {
		if except != noExcept && i == leafIndex(except) {

			continue
		}

		session.handle(message)
	}
	check(initEpoch, except)
}

func (s *SessionTest) broadcastAdd() {

	size := len(s.Sessions)

	broadcastAdd(size-1, size)

}
func (s *SessionTest) broadcastAdd(from int, index int) {
	initSecret := freshSecret()
	idPriv := newIdentityKey()
	cred := NewBasicCredential(s.UserID,s.Scheme,&idPriv)
	initKey,err = := NewClientInitKey(s.CipherSuite, cred)
	assertNotError(t, err, "NewClientInitKey error")
	initKeys := []ClientInitKey{*initKey}

	if (len(s.Sessions) == 0){
		myInitSecret := freshSecret()
		myIdPriv := newIdentityKey()
		myCred := NewBasicCredential(s.UserID,s.Scheme,&myIdPriv)
		myInitKey,err := NewClientInitKey(s.CipherSuite, myCred)
		assertNotError(t, err, "NewClientInitKey error")
		myInitKeys := []ClientInitKey{*initKey}

		commitSecret := freshSecret()
		creator,welcome,err := start(s.GroupID, myInitKey , myInitKeys, commitSecret)
		assertNotError(t, err, "Error starting session")

		joiner,err := join(myInitKeys,*welcome)
		assertNotError(t, err, "Error joining session")

		s.Sessions = append(s.Sessions,creator)
		s.Sessions = append(s.Sessions,joiner)
		return

	}

	initEpoch = s.Sessions[0].CurrentEpoch()
	addSecret = freshSecret()
	welcome,add,err := s.Sessions[from].add(addSecret,*initKey)
	assertNotError(t, err, "Error adding participant")

	next,err = join(initKeys,welcome)
	assertNotError(t, err, "Error joining new participant")

	broadcast(add,index)

	if(index == len(s.Sessions)){
		s.Sessions = append(s.Sessions,next)
	} else if index < len(s.Sessions) {

		s.Sessions[index] = next
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

	//start(groupID []byte, myCIKs []ClientInitKey, otherCIKs []ClientInitKey, initSecret []byte) (*Session, *Welcome, error) {

}

func (s *SessionTest) check(initEpoch Epoch) {

	check(initEpoch, noExcept)
}
func (s *SessionTest) check(initEpoch Epoch, except int) {

	ref := 0

	if except == 0 && len(s.Sessions) > 1 {

		ref = 1
	}

	for i, sess := range s.Sessions {

		if except != noExcept && i == leafIndex(except) {

			continue
		}

		assert.Equal(s.testing, sess.evaluateEquals(s.Sessions[ref]), true)

		pt := []byte{0, 1, 2, 3}
		ct := sess.protect(pt)

		for j, otherSess := range s.Sessions {

			if except != noExcept && i == leafIndex(except) {

				continue
			}

			decryptedPT := otherSess.unprotect(ct)
			assert.Equal(s.testing, pt, decryptedPT)
		}

		assert.NotEqual(s.testing, s.Sessions[ref].CurrentEpoch, initEpoch)

	}

}


