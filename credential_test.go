package mls

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/bifurcation/mint/syntax"
	"github.com/stretchr/testify/require"
)

func makeSerialNumber() (*big.Int, error) {
	serialNumberLimit := big.NewInt(0).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, serialNumberLimit)
}

func makeNBNA() (notBefore time.Time, notAfter time.Time) {
	backdate := time.Hour
	lifetime := 24 * time.Hour
	now := time.Now()
	notBefore = now.Add(-backdate)
	notAfter = now.Add(lifetime - backdate)
	return
}

func newEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	pub , priv, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	return pub, priv
}

// Handy function to create the leaf cert
func makeLeafCert(t *testing.T, parent *x509.Certificate,  parentPrivate interface{}) *x509.Certificate{
	notBefore, notAfter := makeNBNA()
	sn, err := makeSerialNumber()
	require.Nil(t, err)
	certTemplate := &x509.Certificate{
		SerialNumber: sn,
		NotBefore: notBefore,
		NotAfter: notAfter,
		Subject: pkix.Name{
			CommonName: "alice@example.com",
		},
		BasicConstraintsValid: true,
		IsCA: false,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	_, priv := newEd25519(t)
	certData, err := x509.CreateCertificate(rand.Reader, certTemplate, parent, priv.Public(), parentPrivate)
	require.Nil(t, err)
	cert, err := x509.ParseCertificate(certData)
	require.Nil(t, err)
	return cert
}

func makeCertChain(t *testing.T, rootPriv crypto.Signer, depth int) []*x509.Certificate {
	chain := []*x509.Certificate{}

	notBefore, notAfter := makeNBNA()
	sn, err := makeSerialNumber()
	require.Nil(t, err)

	// template for non leaf certs
	caTemplate := &x509.Certificate{
		SerialNumber: sn,
		NotBefore: notBefore,
		NotAfter: notAfter,
		BasicConstraintsValid: true,
		IsCA: true,
		KeyUsage: x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	rootCertData, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, rootPriv.Public(), rootPriv)
	require.Nil(t, err)

	rootCert, err := x509.ParseCertificate(rootCertData)
	require.Nil(t, err)

	chain = append(chain, rootCert)

	// Add intermediate certs
	currPriv := rootPriv
	_, nextPriv := newEd25519(t)
	for len(chain) < depth {
		intCertData, err := x509.CreateCertificate(rand.Reader, caTemplate, chain[len(chain)-1], nextPriv.Public(), currPriv)
		require.Nil(t, err)

		intCert, err := x509.ParseCertificate(intCertData)
		require.Nil(t, err)

		chain = append(chain, intCert)

		currPriv = nextPriv
		_, nextPriv = newEd25519(t)
	}

	leaf := makeLeafCert(t, chain[len(chain)-1], nextPriv)
	chain = append(chain, leaf)
	return chain
}

func makeX509Credential(t *testing.T, priv *SignaturePrivateKey) (*Credential, []*x509.Certificate) {
	rootPub, rootPriv := newEd25519(t)
	sigPriv := SignaturePrivateKey{
		Data: rootPriv,
		PublicKey: SignaturePublicKey{
			Data: rootPub,
		},
	}

	// setup cert chain to create x.509 MLS credential
	chain := makeCertChain(t, rootPriv, 1)

	if priv != nil {
		// for error flow simulation
		return NewX509Credential(chain, priv), chain
	}

	return NewX509Credential(chain, &sigPriv), chain
}


func TestBasicCredential(t *testing.T) {
	identity := []byte("res ipsa")
	scheme := Ed25519
	priv, err := scheme.Generate()
	require.Nil(t, err)

	cred := NewBasicCredential(identity, scheme, &priv)
	require.True(t, cred.Equals(*cred))
	require.Equal(t, cred.Type(), CredentialTypeBasic)
	require.Equal(t, cred.Scheme(), scheme)
	require.Equal(t, *cred.PublicKey(), priv.PublicKey)
}

func TestX509Credential(t *testing.T) {
	cred, chain := makeX509Credential(t, nil)

	require.NotNil(t, cred)
	require.True(t, cred.Equals(*cred))
	require.Equal(t, cred.Type(), CredentialTypeX509)
	require.Equal(t, cred.Scheme(), Ed25519)
	require.NotNil(t, cred.PublicKey())

	// chain goes from root -> leaf
	// trusted goes form leaf -> root
	trusted := chain[:]
	for left, right := 0, len(trusted)-1; left < right; left, right = left+1, right-1 {
		trusted[left], trusted[right] = trusted[right], trusted[left]
	}
	require.Nil(t, cred.X509.Verify(trusted))

}

func TestCredentialErrorCases(t *testing.T) {
	cred := Credential{nil, nil, nil}

	require.Panics(t, func() { cred.Equals(cred) })
	require.Panics(t, func() { cred.Type() })
	require.Panics(t, func() { cred.PublicKey() })
	require.Panics(t, func() { cred.Scheme() })
	require.Panics(t, func() { syntax.Marshal(cred) })

	// wrong priv key
	scheme := Ed25519
	priv, err := scheme.Generate()
	require.Nil(t, err)
	require.Panics(t, func() { makeX509Credential(t, &priv) })
}

func TestCredentialPrivateKey(t *testing.T) {

	identity := []byte("res ipsa")
	scheme := Ed25519
	priv, err := scheme.Generate()
	require.Nil(t, err)

	cred := NewBasicCredential(identity, scheme, &priv)
	priv, ok := cred.PrivateKey()
	require.True(t, ok)
	require.NotEmpty(t, priv)

	// remove sensitive info before exporting
	cred.RemovePrivateKey()
	require.Nil(t, cred.privateKey)

	priv, ok = cred.PrivateKey()
	require.False(t, ok)
	require.Empty(t, priv)
}
