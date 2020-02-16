package mls

import (
	"fmt"
	"reflect"
)

type CredentialType uint8

const (
	CredentialTypeInvalid CredentialType = 0xff
	CredentialTypeBasic   CredentialType = 0
	CredentialTypeX509    CredentialType = 1
)

func (ct CredentialType) ValidForTLS() error {
	return validateEnum(ct, CredentialTypeBasic)
}

// struct {
//     opaque identity<0..2^16-1>;
//     SignatureScheme algorithm;
//     SignaturePublicKey public_key;
// } BasicCredential;
type BasicCredential struct {
	Identity           []byte `tls:"head=2"`
	SignatureScheme    SignatureScheme
	SignaturePublicKey SignaturePublicKey
}

type X509Credential struct {
	CertData []byte `tls:"head=3"`
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
	// TODO(#35) X509       *X509Credential
	Basic      *BasicCredential
	privateKey *SignaturePrivateKey
}

func NewBasicCredential(userId []byte, scheme SignatureScheme, priv *SignaturePrivateKey) *Credential {
	basicCredential := &BasicCredential{
		Identity:           userId,
		SignatureScheme:    scheme,
		SignaturePublicKey: priv.PublicKey,
	}
	return &Credential{Basic: basicCredential, privateKey: priv}
}

// compare the public aspects
func (c Credential) Equals(o Credential) bool {
	switch {
	// TODO(#35) case c.X509 != nil:
	case c.Basic != nil:
		return reflect.DeepEqual(c.Basic, o.Basic)
	}
	return false
}

func (c Credential) Type() CredentialType {
	switch {
	// TODO(#35) case c.X509 != nil:
	case c.Basic != nil:
		return CredentialTypeBasic
	default:
		return CredentialTypeInvalid
	}
}

func (c *Credential) SetPrivateKey(priv SignaturePrivateKey) {
	c.privateKey = &priv
}

func (c *Credential) RemovePrivateKey() {
	c.privateKey = nil
}

func (c Credential) PrivateKey() (SignaturePrivateKey, bool) {
	if c.privateKey == nil {
		return SignaturePrivateKey{}, false
	}

	return *c.privateKey, true
}

func (c Credential) PublicKey() *SignaturePublicKey {
	switch {
	// TODO(#35) case c.X509 != nil:
	case c.Basic != nil:
		return &c.Basic.SignaturePublicKey
	default:
		panic("mls.credential: Can't retrieve PublicKey")
	}
}

func (c Credential) Scheme() SignatureScheme {
	switch {
	// TODO(#35) case c.X509 != nil:
	case c.Basic != nil:
		return c.Basic.SignatureScheme
	default:
		panic("mls.credential: Can't retrieve SignatureScheme")
	}
}

func (c Credential) MarshalTLS() ([]byte, error) {
	s := NewWriteStream()
	credentialType := c.Type()
	err := s.Write(credentialType)
	if err != nil {
		return nil, err
	}
	switch credentialType {
	// TODO(#35) case CredentialTypeX509
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
	s := NewReadStream(data)
	var credentialType CredentialType
	_, err := s.Read(&credentialType)
	if err != nil {
		return 0, err
	}

	switch credentialType {
	// TODO(#35) case CredentialTypeX509
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
