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

func broadcastAdd() {

}
func broadcastAdd(from int, index int) {

}

func setupSession(t *testing.T) SessionTest {
	sessionTest := SessionTest{}

	sessionTest.CipherSuite = P256_SHA256_AES128GCM
	sessionTest.Scheme = Ed25519
	sessionTest.GroupSize = 5
	sessionTest.SecretSize = 32
	sessionTest.GroupID = []byte{0x01, 0x02, 0x03, 0x04}
	sessionTest.UserID = []byte{0x04, 0x05, 0x06, 0x07}
	sessionTest.numSessions = 1

	for i := 0; i < numSession; i++ {

		for j := 0; j < groupSize; j++ {

			broadcastAdd()
		}
		//sessionTestSession.append()
	}

	//start(groupID []byte, myCIKs []ClientInitKey, otherCIKs []ClientInitKey, initSecret []byte) (*Session, *Welcome, error) {

}
