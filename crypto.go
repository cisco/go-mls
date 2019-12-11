package mls

import (
	"crypto/rand"

	"golang.org/x/crypto/ed25519"
)

type CipherSuite uint16

type SignaturePrivateKey struct {
	priv      ed25519.PrivateKey
	PublicKey SignaturePublicKey
}


// opaque SignaturePublicKey<1..2^16-1>;
type SignaturePublicKey struct {
	pub ed25519.PublicKey `tls:"head=2"`
}


func NewSignaturePrivateKey() SignaturePrivateKey {
	// XXX: Ignoring error
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return SignaturePrivateKey{
		priv:      priv,
		PublicKey: SignaturePublicKey{pub: pub},
	}
}
