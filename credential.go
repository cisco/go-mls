package mls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"fmt"
	"reflect"

	"github.com/cisco/go-tls-syntax"
)

type CredentialType uint8

const (
	CredentialTypeInvalid CredentialType = 255
	CredentialTypeBasic   CredentialType = 0
	CredentialTypeX509    CredentialType = 1
)

func (ct CredentialType) ValidForTLS() error {
	return validateEnum(ct, CredentialTypeBasic, CredentialTypeX509)
}

// struct {
//     opaque identity<0..2^16-1>;
//     SignatureScheme algorithm;
//     SignaturePublicKey public_key;
// } BasicCredential;
type BasicCredential struct {
	Identity        []byte `tls:"head=2"`
	SignatureScheme SignatureScheme
	PublicKey       SignaturePublicKey
}

// case x509:
//     opaque cert_data<1..2^24-1>;
type X509Credential struct {
	Chain []*x509.Certificate
}

func (cred X509Credential) Scheme() SignatureScheme {
	leaf := cred.Chain[0]
	switch leaf.PublicKeyAlgorithm {
	case x509.ECDSA:
		ecKey := leaf.PublicKey.(*ecdsa.PublicKey)
		switch ecKey.Curve {
		case elliptic.P256():
			return ECDSA_SECP256R1_SHA256
		case elliptic.P521():
			return ECDSA_SECP521R1_SHA512
		default:
			panic("Unsupported elliptic curve")
		}

	case x509.Ed25519:
		return Ed25519
	}

	panic("Unsupported algorithm in certificate")
}

func (cred X509Credential) PublicKey() *SignaturePublicKey {
	switch pub := cred.Chain[0].PublicKey.(type) {
	case *ecdsa.PublicKey:
		keyData := elliptic.Marshal(pub.Curve, pub.X, pub.Y)
		return &SignaturePublicKey{Data: keyData}

	case ed25519.PublicKey:
		return &SignaturePublicKey{Data: pub}
	}

	panic("Unsupported public key type in certificate")
}

type certChainData struct {
	Data []byte `tls:"head=3"`
}

func (cred X509Credential) Equals(other *X509Credential) bool {
	if len(cred.Chain) != len(other.Chain) {
		return false
	}

	for i, cert := range cred.Chain {
		if !cert.Equal(other.Chain[i]) {
			return false
		}
	}

	return true
}

func (cred X509Credential) MarshalTLS() ([]byte, error) {
	allCerts := []byte{}
	for _, cert := range cred.Chain {
		allCerts = append(allCerts, cert.Raw...)
	}

	return syntax.Marshal(certChainData{allCerts})
}

func (cred *X509Credential) UnmarshalTLS(data []byte) (int, error) {
	allCerts := new(certChainData)
	read, err := syntax.Unmarshal(data, allCerts)
	if err != nil {
		return 0, err
	}

	cred.Chain, err = x509.ParseCertificates(allCerts.Data)
	if err != nil {
		return 0, err
	}

	return read, nil
}

// This is essentially a copy of what is in crypto/x509, but with things exposed
// that are hidden in that module.
type certPool struct {
	byKeyID map[string]*x509.Certificate
	byName  map[string]*x509.Certificate
}

func newCertPool(trusted []*x509.Certificate) *certPool {
	pool := &certPool{
		byKeyID: map[string]*x509.Certificate{},
		byName:  map[string]*x509.Certificate{},
	}

	for _, cert := range trusted {
		ski := string(cert.SubjectKeyId)
		name := string(cert.RawSubject)

		pool.byName[name] = cert
		if len(ski) > 0 {
			pool.byKeyID[ski] = cert
		}
	}

	return pool
}

func (pool certPool) parent(cert *x509.Certificate) (*x509.Certificate, bool) {
	aki := string(cert.AuthorityKeyId)
	name := string(cert.RawIssuer)

	if parent, ok := pool.byKeyID[aki]; len(aki) > 0 && ok {
		return parent, true
	}

	if parent, ok := pool.byName[name]; ok {
		return parent, true
	}

	return nil, false
}

// XXX(RLB): This is a very simple chain validation, just looking at signatures
// and whatever basic hop-by-hop policy is applied by CheckSignatureFrom.  More
// complex things like name constraints are not considered.  They would be if we
// were using x509.Certificate.Verify, but that method (1) requires a DNS name
// as the authentication anchor, and (2) builds its own chain without strict
// ordering.
func (cred X509Credential) Verify(trusted []*x509.Certificate) error {
	pool := newCertPool(trusted)

	var curr, next *x509.Certificate
	for i := 0; i < len(cred.Chain)-1; i++ {
		curr = cred.Chain[i]
		next = cred.Chain[i+1]

		// If there is a valid signature from a trusted certificate, the chain is valid
		parent, ok := pool.parent(curr)
		if ok && curr.CheckSignatureFrom(parent) == nil {
			return nil
		}

		// Otherwise the cert must be signed by the next cert in the chain
		if err := curr.CheckSignatureFrom(next); err != nil {
			return err
		}
	}

	// If no previous certificate has been signed under a trusted certificate,
	// then the last certificate in the chain must be signed by a trusted
	// certificate
	last := cred.Chain[len(cred.Chain)-1]
	parent, ok := pool.parent(last)
	if !ok {
		return fmt.Errorf("No candidate trust anchor found")
	}

	return last.CheckSignatureFrom(parent)
}

//	struct {
//		CredentialType credential_type;
//		select (Credential.credential_type) {
//			case basic:
//				BasicCredential;
//			case x509:
//				opaque cert_data<1..2^24-1>;
//		};
//} Credential;
type Credential struct {
	X509  *X509Credential
	Basic *BasicCredential
}

func NewBasicCredential(userId []byte, scheme SignatureScheme, pub SignaturePublicKey) *Credential {
	basicCredential := &BasicCredential{
		Identity:        userId,
		SignatureScheme: scheme,
		PublicKey:       pub,
	}
	return &Credential{Basic: basicCredential}
}

func NewX509Credential(chain []*x509.Certificate) (*Credential, error) {
	if len(chain) == 0 {
		return nil, fmt.Errorf("Malformed credential: At least one certificate is required")
	}

	x509Credential := &X509Credential{
		Chain: chain,
	}

	return &Credential{X509: x509Credential}, nil
}

// compare the public aspects
func (c Credential) Equals(o Credential) bool {
	switch c.Type() {
	case CredentialTypeX509:
		return c.X509.Equals(o.X509)
	case CredentialTypeBasic:
		return reflect.DeepEqual(c.Basic, o.Basic)
	default:
		panic("Malformed credential")
	}
}

func (c Credential) Type() CredentialType {
	switch {
	case c.X509 != nil:
		return CredentialTypeX509
	case c.Basic != nil:
		return CredentialTypeBasic
	default:
		panic("Malformed credential")
	}
}

func (c Credential) Identity() []byte {
	switch c.Type() {
	case CredentialTypeX509:
		return c.X509.Chain[0].RawSubject
	case CredentialTypeBasic:
		return c.Basic.Identity
	default:
		panic("mls.credential: Can't retrieve PublicKey")
	}
}

func (c Credential) Scheme() SignatureScheme {
	switch c.Type() {
	case CredentialTypeX509:
		return c.X509.Scheme()
	case CredentialTypeBasic:
		return c.Basic.SignatureScheme
	default:
		panic("mls.credential: Can't retrieve SignatureScheme")
	}
}

func (c Credential) PublicKey() *SignaturePublicKey {
	switch c.Type() {
	case CredentialTypeX509:
		return c.X509.PublicKey()
	case CredentialTypeBasic:
		return &c.Basic.PublicKey
	default:
		panic("mls.credential: Can't retrieve PublicKey")
	}
}

func (c Credential) MarshalTLS() ([]byte, error) {
	s := syntax.NewWriteStream()
	credentialType := c.Type()
	err := s.Write(credentialType)
	if err != nil {
		return nil, err
	}
	switch credentialType {
	case CredentialTypeX509:
		err = s.Write(c.X509)
	case CredentialTypeBasic:
		err = s.Write(c.Basic)
	default:
		err = fmt.Errorf("mls.credential: CredentialType type not allowed")
	}

	if err != nil {
		return nil, err
	}

	return s.Data(), nil
}

func (c *Credential) UnmarshalTLS(data []byte) (int, error) {
	s := syntax.NewReadStream(data)
	var credentialType CredentialType
	_, err := s.Read(&credentialType)
	if err != nil {
		return 0, err
	}

	switch credentialType {
	case CredentialTypeX509:
		c.X509 = new(X509Credential)
		_, err = s.Read(c.X509)
	case CredentialTypeBasic:
		c.Basic = new(BasicCredential)
		_, err = s.Read(c.Basic)
	default:
		err = fmt.Errorf("mls.credential: CredentialType type not allowed %v", err)
	}

	if err != nil {
		return 0, err
	}
	return s.Position(), nil
}
