package mls

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/bifurcation/mint/syntax"
	"github.com/stretchr/testify/require"
)

var (
	caTemplate = &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	leafTemplate = &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
)

func newEd25519(t *testing.T) ed25519.PrivateKey {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.Nil(t, err)
	return priv
}

func makeCert(t *testing.T, template, parent *x509.Certificate, parentPriv crypto.Signer, addSKI bool) (crypto.Signer, *x509.Certificate) {
	backdate := time.Hour
	lifetime := 24 * time.Hour
	skiSize := 4 // bytes

	// Set expiry
	template.NotBefore = time.Now().Add(-backdate)
	template.NotAfter = template.NotBefore.Add(lifetime)

	// Set serial number
	serialNumberLimit := big.NewInt(0).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.Nil(t, err)
	template.SerialNumber = serialNumber

	// Add random SKI if requried
	template.SubjectKeyId = nil
	if addSKI {
		template.SubjectKeyId = make([]byte, skiSize)
		rand.Read(template.SubjectKeyId)
	}

	// Generate and parse the certificate
	priv := parentPriv
	realParent := template
	if parent != nil {
		priv = newEd25519(t)
		realParent = parent
	}

	certData, err := x509.CreateCertificate(rand.Reader, template, realParent, priv.Public(), parentPriv)
	require.Nil(t, err)
	cert, err := x509.ParseCertificate(certData)
	require.Nil(t, err)
	return priv, cert
}

func makeCertChain(t *testing.T, rootPriv crypto.Signer, depth int, addSKI bool) (*SignaturePrivateKey, *x509.Certificate, []*x509.Certificate) {
	chain := make([]*x509.Certificate, depth)

	_, rootCert := makeCert(t, caTemplate, nil, rootPriv, addSKI)

	currPriv := rootPriv
	cert := rootCert
	for i := depth - 1; i > 0; i-- {
		currPriv, cert = makeCert(t, caTemplate, cert, currPriv, addSKI)
		chain[i] = cert
	}

	currPriv, cert = makeCert(t, leafTemplate, cert, currPriv, addSKI)
	chain[0] = cert

	sigPriv := &SignaturePrivateKey{
		Data: currPriv.(ed25519.PrivateKey),
		PublicKey: SignaturePublicKey{
			Data: currPriv.Public().(ed25519.PublicKey),
		},
	}

	return sigPriv, rootCert, chain
}

func makeX509Credential(t *testing.T, depth int, addSKI bool) (*Credential, *x509.Certificate) {
	rootPriv := newEd25519(t)
	leafPriv, rootCert, chain := makeCertChain(t, rootPriv, depth, addSKI)

	cred, err := NewX509Credential(chain, leafPriv)
	require.Nil(t, err)
	return cred, rootCert
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

	credData, err := syntax.Marshal(cred)
	require.Nil(t, err)

	cred2 := new(Credential)
	_, err = syntax.Unmarshal(credData, cred2)
	require.Nil(t, err)
}

func TestX509Credential(t *testing.T) {
	cred, _ := makeX509Credential(t, 3, true)

	require.NotNil(t, cred)
	require.True(t, cred.Equals(*cred))
	require.Equal(t, cred.Type(), CredentialTypeX509)
	require.Equal(t, cred.Scheme(), Ed25519)
	require.NotNil(t, cred.PublicKey())

	credData, err := syntax.Marshal(cred)
	require.Nil(t, err)

	cred2 := new(Credential)
	_, err = syntax.Unmarshal(credData, cred2)
	require.Nil(t, err)
}

func TestX509CredentialOne(t *testing.T) {
	cred, root := makeX509Credential(t, 1, false)
	trusted := []*x509.Certificate{root}
	require.Nil(t, cred.X509.Verify(trusted))
}

func TestX509CredentialVerifyByName(t *testing.T) {
	cred, root := makeX509Credential(t, 3, false)
	trusted := []*x509.Certificate{root}
	require.Nil(t, cred.X509.Verify(trusted))
}

func TestX509CredentialVerifyBySKI(t *testing.T) {
	cred, root := makeX509Credential(t, 3, true)
	trusted := []*x509.Certificate{root}
	require.Nil(t, cred.X509.Verify(trusted))
}

func TestCredentialErrorCases(t *testing.T) {
	cred := Credential{nil, nil, nil}

	require.Panics(t, func() { cred.Equals(cred) })
	require.Panics(t, func() { cred.Type() })
	require.Panics(t, func() { cred.PublicKey() })
	require.Panics(t, func() { cred.Scheme() })
	require.Panics(t, func() { syntax.Marshal(cred) })

	// Wrong priv key for X.509 Credential
	rootPriv := newEd25519(t)
	_, _, chain := makeCertChain(t, rootPriv, 3, false)
	altPriv, err := Ed25519.Generate()
	require.Nil(t, err)

	_, err = NewX509Credential(chain, &altPriv)
	require.Error(t, err)

	// No certificate chain for X.509 Credential
	_, err = NewX509Credential(nil, &altPriv)
	require.Error(t, err)
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
