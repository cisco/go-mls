package mls

import (
	"testing"
)

func TestBasicCredential(t *testing.T) {
	identity := []byte("res ipsa")
	scheme := Ed25519
	priv, err := scheme.Generate()
	assertNotError(t, err, "Error generating private key")

	cred := NewBasicCredential(identity, scheme, &priv)
	assertTrue(t, cred.Equals(*cred), "Credential not equal to self")
	assertEquals(t, cred.Type(), CredentialTypeBasic)
	assertEquals(t, cred.Scheme(), scheme)
	assertDeepEquals(t, *cred.PublicKey(), priv.PublicKey)
}

func TestCredentialErrorCases(t *testing.T) {
	cred0 := Credential{nil, nil}

	assertTrue(t, !cred0.Equals(cred0), "Bad credentials should not be equal")
	assertEquals(t, cred0.Type(), CredentialTypeInvalid)
	assertPanic(t, func() { cred0.PublicKey() }, "Public key for bad credential")
	assertPanic(t, func() { cred0.Scheme() }, "Scheme for bad credential")

	_, err := cred0.MarshalTLS()
	assertError(t, err, "Marshal for bad credential")
}
