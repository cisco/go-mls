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

	identityPrivs  []SignaturePrivateKey
	credentials    []Credential
	initPrivs      []HPKEPrivateKey
	clientInitKeys = make([]ClientInitKey, groupSize)
	states         []State

	testMessage = unhex("01020304")
)

func setup() {
	var cik *ClientInitKey = nil
	for i := 0; i < groupSize; i++ {
		// cred gen
		sigPriv, _ := scheme.Generate()
		basicCredential = &BasicCredential{
			Identity:           userId,
			SignatureScheme:    scheme,
			SignaturePublicKey: sigPriv.PublicKey,
		}
		credentialBasic = Credential{Basic: basicCredential, privateKey: &sigPriv}

		//cik gen
		cik = newClientInitKey(suite, &credentialBasic)
		cik.Id = uint8(i)
		// save all the materials
		identityPrivs = append(identityPrivs, sigPriv)
		credentials = append(credentials, credentialBasic)
		initPrivs = append(initPrivs, ikPriv)
		clientInitKeys[i] = *cik
		cik = nil
		//dump(clientInitKeys)
	}
}

func dump(ciks []ClientInitKey) {
	fmt.Println("---- DUMP -----")
	for _, cik := range ciks {
		fmt.Printf("%d priv %x pub %x\n", cik.Id, cik.privateKey.Data, cik.InitKey.Data)
	}
}

func TestState_TwoPerson(t *testing.T) {
	setup()
	// creator's state
	dump(clientInitKeys)
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

	assertEquals(t, *first1, *second0)

	/// Verify that they can exchange protected messages
	ct := first1.protect(testMessage)
	pt, err := second0.unprotect(ct)
	assertNotError(t, err, "unprotect failure")
	assertByteEquals(t, pt, testMessage)

}
