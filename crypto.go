package mls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"

	"github.com/cisco/go-hpke"
	"github.com/cisco/go-tls-syntax"
	"golang.org/x/crypto/ed25519"
)

///
/// Signature schemes
///

type SignaturePrivateKey struct {
	Data      []byte `tls:"head=2"`
	PublicKey SignaturePublicKey
}

type SignaturePublicKey struct {
	Data []byte `tls:"head=2"`
}

func (pub SignaturePublicKey) Equals(other SignaturePublicKey) bool {
	return bytes.Equal(pub.Data, other.Data)
}

type SignatureScheme interface {
	PrivateKeySize() int
	Sign(skS SignaturePrivateKey, message []byte) ([]byte, error)
	Verify(pkS SignaturePublicKey, message, signature []byte) bool

	DeriveKeyPair(ikm []byte) (SignaturePrivateKey, SignaturePublicKey, error)
}

type ecdsaScheme struct {
	Digest func() hash.Hash
	Curve  elliptic.Curve
}

func (s ecdsaScheme) PrivateKeySize() int {
	return len(s.Curve.Params().N.Bytes())
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (s ecdsaScheme) Sign(skS SignaturePrivateKey, message []byte) ([]byte, error) {
	h := s.Digest()
	h.Write(message)
	digest := h.Sum(nil)

	ecPriv := &ecdsa.PrivateKey{
		D:         big.NewInt(0).SetBytes(skS.Data),
		PublicKey: ecdsa.PublicKey{Curve: s.Curve},
	}
	return ecPriv.Sign(rand.Reader, digest, nil)
}

func (s ecdsaScheme) Verify(pkS SignaturePublicKey, message, signature []byte) bool {
	h := s.Digest()
	h.Write(message)
	digest := h.Sum(nil)

	x, y := elliptic.Unmarshal(s.Curve, pkS.Data)

	var sig ecdsaSignature
	_, err := asn1.Unmarshal(signature, &sig)
	if err != nil {
		return false
	}

	ecPub := &ecdsa.PublicKey{Curve: s.Curve, X: x, Y: y}
	return ecdsa.Verify(ecPub, digest, sig.R, sig.S)
}

func (s ecdsaScheme) privateKeyBitmask() uint8 {
	switch s.Curve.Params().Name {
	case "P-256":
		return 0xFF
	case "P-521":
		return 0x01
	}
	panic(fmt.Sprintf("Unsupported curve: %s", s.Curve.Params().Name))
}

func (s ecdsaScheme) DeriveKeyPair(ikm []byte) (SignaturePrivateKey, SignaturePublicKey, error) {
	// This follows the same general procedure as the DHKEM DeriveKeyPair, with
	// some irrelevant branches / loops pruned.
	prkHash := s.Digest()
	prkHash.Write([]byte("dkp_prk"))
	prkHash.Write(ikm)

	d := prkHash.Sum(nil)[:s.PrivateKeySize()]
	d[0] &= s.privateKeyBitmask()
	x, y := s.Curve.Params().ScalarBaseMult(d)

	priv := SignaturePrivateKey{
		Data:      d,
		PublicKey: SignaturePublicKey{Data: elliptic.Marshal(s.Curve, x, y)},
	}
	return priv, priv.PublicKey, nil
}

type ed25519Scheme struct{}

func (s ed25519Scheme) PrivateKeySize() int {
	return 32
}

func (s ed25519Scheme) Sign(skS SignaturePrivateKey, message []byte) ([]byte, error) {
	priv25519 := ed25519.PrivateKey(skS.Data)
	return ed25519.Sign(priv25519, message), nil
}

func (s ed25519Scheme) Verify(pkS SignaturePublicKey, message, signature []byte) bool {
	pub25519 := ed25519.PublicKey(pkS.Data)
	return ed25519.Verify(pub25519, message, signature)
}

func (s ed25519Scheme) DeriveKeyPair(ikm []byte) (SignaturePrivateKey, SignaturePublicKey, error) {
	h := sha256.New()
	h.Write([]byte("dkp_prk"))
	h.Write(ikm)

	priv25519 := ed25519.NewKeyFromSeed(h.Sum(nil))
	pub25519 := priv25519.Public().(ed25519.PublicKey)
	priv := SignaturePrivateKey{
		Data:      priv25519,
		PublicKey: SignaturePublicKey{pub25519},
	}
	return priv, priv.PublicKey, nil
}

///
/// Ciphersuites
///
type CiphersuiteID uint16

const (
	X25519_AES128GCM_SHA256_Ed25519        CiphersuiteID = 0x0001 // REQUIRED
	P256_AES128GCM_SHA256_P256             CiphersuiteID = 0x0002
	X25519_CHACHA20POLY1305_SHA256_Ed25519 CiphersuiteID = 0x0003
	X448_AES256GCM_SHA512_Ed448            CiphersuiteID = 0x0004 // UNSUPPORTED
	P521_AES256GCM_SHA512_P521             CiphersuiteID = 0x0005
	X448_CHACHA20POLY1305_SHA512_Ed448     CiphersuiteID = 0x0006 // UNSUPPORTED
)

var (
	AllSupportedCiphesuites = []CiphersuiteID{
		X25519_AES128GCM_SHA256_Ed25519,
		P256_AES128GCM_SHA256_P256,
		X25519_CHACHA20POLY1305_SHA256_Ed25519,
		P521_AES256GCM_SHA512_P521,
	}

	cipherDetails = map[CiphersuiteID]struct {
		KDF       hpke.KDFID
		KEM       hpke.KEMID
		AEAD      hpke.AEADID
		Digest    func() hash.Hash
		Signature SignatureScheme
	}{
		X25519_AES128GCM_SHA256_Ed25519: {
			KEM:       hpke.DHKEM_X25519,
			KDF:       hpke.KDF_HKDF_SHA256,
			AEAD:      hpke.AEAD_AESGCM128,
			Digest:    sha256.New,
			Signature: ed25519Scheme{},
		},
		P256_AES128GCM_SHA256_P256: {
			KEM:       hpke.DHKEM_P256,
			KDF:       hpke.KDF_HKDF_SHA256,
			AEAD:      hpke.AEAD_AESGCM128,
			Digest:    sha256.New,
			Signature: ecdsaScheme{Digest: sha256.New, Curve: elliptic.P256()},
		},
		X25519_CHACHA20POLY1305_SHA256_Ed25519: {
			KEM:       hpke.DHKEM_X25519,
			KDF:       hpke.KDF_HKDF_SHA256,
			AEAD:      hpke.AEAD_CHACHA20POLY1305,
			Digest:    sha256.New,
			Signature: ed25519Scheme{},
		},
		P521_AES256GCM_SHA512_P521: {
			KEM:       hpke.DHKEM_P521,
			KDF:       hpke.KDF_HKDF_SHA512,
			AEAD:      hpke.AEAD_AESGCM256,
			Digest:    sha512.New,
			Signature: ecdsaScheme{Digest: sha512.New, Curve: elliptic.P521()},
		},
	}
)

type Ciphersuite struct {
	HPKE      hpke.CipherSuite
	Digest    func() hash.Hash
	Signature SignatureScheme

	ID         CiphersuiteID
	KeySize    int
	NonceSize  int
	SecretSize int
}

func NewCipherSuite(id CiphersuiteID) (Ciphersuite, error) {
	details, ok := cipherDetails[id]
	if !ok {
		return Ciphersuite{}, fmt.Errorf("Unsupported ciphersuite %d", id)
	}

	hpkeCS, err := hpke.AssembleCipherSuite(details.KEM, details.KDF, details.AEAD)
	if err != nil {
		return Ciphersuite{}, err
	}

	cs := Ciphersuite{
		HPKE:       hpkeCS,
		Signature:  details.Signature,
		Digest:     details.Digest,
		ID:         id,
		KeySize:    hpkeCS.AEAD.KeySize(),
		NonceSize:  hpkeCS.AEAD.NonceSize(),
		SecretSize: hpkeCS.KDF.OutputSize(),
	}
	return cs, nil
}

func (cs Ciphersuite) MarshalTLS() ([]byte, error) {
	return syntax.Marshal(cs.ID)
}

func (cs *Ciphersuite) UnmarshalTLS(data []byte) (int, error) {
	var id CiphersuiteID
	read, err := syntax.Unmarshal(data, &id)
	if err != nil {
		return 0, err
	}

	*cs, err = NewCipherSuite(id)
	if err != nil {
		return 0, err
	}

	return read, nil
}

func (cs Ciphersuite) String() string {
	switch cs.ID {
	case X25519_AES128GCM_SHA256_Ed25519:
		return "X25519_AES128GCM_SHA256_Ed25519"
	case P256_AES128GCM_SHA256_P256:
		return "P256_AES128GCM_SHA256_P256"
	case X25519_CHACHA20POLY1305_SHA256_Ed25519:
		return "X25519_CHACHA20POLY1305_SHA256_Ed25519"
	case X448_AES256GCM_SHA512_Ed448:
		return "X448_AES256GCM_SHA512_Ed448"
	case P521_AES256GCM_SHA512_P521:
		return "P521_AES256GCM_SHA512_P521"
	case X448_CHACHA20POLY1305_SHA512_Ed448:
		return "X448_CHACHA20POLY1305_SHA512_Ed448"
	}

	return "UnknownCiphersuite"
}

func (cs Ciphersuite) zero() []byte {
	return bytes.Repeat([]byte{0x00}, cs.SecretSize)
}

func (cs Ciphersuite) NewHMAC(key []byte) hash.Hash {
	return hmac.New(cs.Digest, key)
}

type kdfLabel struct {
	Length  uint16
	Label   []byte `tls:"head=1"`
	Context []byte `tls:"head=4"`
}

func (cs Ciphersuite) expandWithLabel(secret []byte, label string, context []byte, length int) []byte {
	mlsLabel := []byte("mls10 " + label)
	labelData, err := syntax.Marshal(kdfLabel{uint16(length), mlsLabel, context})
	if err != nil {
		panic(fmt.Errorf("Error marshaling HKDF label: %v", err))
	}

	return cs.HPKE.KDF.Expand(secret, labelData, length)
}

func (cs Ciphersuite) deriveSecret(secret []byte, label string) []byte {
	return cs.expandWithLabel(secret, label, nil, cs.SecretSize)
}

type treeContext struct {
	Node       NodeIndex
	Generation uint32
}

func (cs Ciphersuite) deriveTreeSecret(secret []byte, label string, node NodeIndex, generation uint32, length int) []byte {
	ctx, err := syntax.Marshal(treeContext{node, generation})
	if err != nil {
		panic(fmt.Errorf("Error marshaling application context: %v", err))
	}

	return cs.expandWithLabel(secret, label, ctx, length)
}

///
/// HPKE
///

type HPKEPrivateKey struct {
	Data      []byte `tls:"head=2"`
	PublicKey HPKEPublicKey
}

type HPKEPublicKey struct {
	Data []byte `tls:"head=2"`
}

func (k HPKEPublicKey) Equals(o HPKEPublicKey) bool {
	return bytes.Equal(k.Data, o.Data)
}

type HPKECiphertext struct {
	KEMOutput  []byte `tls:"head=2"`
	Ciphertext []byte `tls:"head=2"`
}

func (cs Ciphersuite) GenerateHPKE() (HPKEPrivateKey, error) {
	seed := make([]byte, cs.HPKE.KEM.PrivateKeySize())
	rand.Read(seed)
	return cs.DeriveHPKE(seed)
}

func (cs Ciphersuite) DeriveHPKE(seed []byte) (HPKEPrivateKey, error) {
	priv, pub, err := cs.HPKE.KEM.DeriveKeyPair(seed)
	if err != nil {
		return HPKEPrivateKey{}, nil
	}

	key := HPKEPrivateKey{
		Data:      cs.HPKE.KEM.SerializePrivateKey(priv),
		PublicKey: HPKEPublicKey{cs.HPKE.KEM.SerializePublicKey(pub)},
	}
	return key, nil
}

func (cs Ciphersuite) EncryptHPKE(pub HPKEPublicKey, aad, pt []byte) (HPKECiphertext, error) {
	pkR, err := cs.HPKE.KEM.DeserializePublicKey(pub.Data)
	if err != nil {
		return HPKECiphertext{}, err
	}

	enc, ctx, err := hpke.SetupBaseS(cs.HPKE, rand.Reader, pkR, nil)
	if err != nil {
		return HPKECiphertext{}, err
	}

	ct := ctx.Seal(aad, pt)
	return HPKECiphertext{enc, ct}, nil
}

func (cs Ciphersuite) DecryptHPKE(priv HPKEPrivateKey, aad []byte, ct HPKECiphertext) ([]byte, error) {
	skR, err := cs.HPKE.KEM.DeserializePrivateKey(priv.Data)
	if err != nil {
		return nil, err
	}

	ctx, err := hpke.SetupBaseR(cs.HPKE, skR, ct.KEMOutput, nil)
	if err != nil {
		return nil, err
	}

	return ctx.Open(aad, ct.Ciphertext)
}

///
/// Signing
///

func (cs Ciphersuite) GenerateSignature() (SignaturePrivateKey, error) {
	seed := make([]byte, cs.Signature.PrivateKeySize())
	rand.Read(seed)
	return cs.DeriveSignature(seed)
}

func (cs Ciphersuite) DeriveSignature(seed []byte) (SignaturePrivateKey, error) {
	priv, _, err := cs.Signature.DeriveKeyPair(seed)
	return priv, err
}

func (cs Ciphersuite) Sign(skS SignaturePrivateKey, message []byte) ([]byte, error) {
	return cs.Signature.Sign(skS, message)
}

func (cs Ciphersuite) Verify(pkS SignaturePublicKey, message, signature []byte) bool {
	return cs.Signature.Verify(pkS, message, signature)
}
