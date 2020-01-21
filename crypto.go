package mls

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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

	"github.com/bifurcation/hpke"
	"github.com/bifurcation/mint/syntax"
	"golang.org/x/crypto/ed25519"
)

type CipherSuite uint16

const (
	P256_SHA256_AES128GCM   CipherSuite = 0x0000
	P521_SHA512_AES256GCM   CipherSuite = 0x0010
	X25519_SHA256_AES128GCM CipherSuite = 0x0001
	X448_SHA512_AES256GCM   CipherSuite = 0x0011
)

func (cs CipherSuite) supported() bool {
	switch cs {
	case P256_SHA256_AES128GCM, P521_SHA512_AES256GCM:
		fallthrough
	case X25519_SHA256_AES128GCM, X448_SHA512_AES256GCM:
		return true
	}

	return false
}

func (cs CipherSuite) String() string {
	switch cs {
	case P256_SHA256_AES128GCM:
		return "P256_SHA256_AES128GCM"
	case X25519_SHA256_AES128GCM:
		return "X25519_SHA256_AES128GCM"
	case P521_SHA512_AES256GCM:
		return "P521_SHA512_AES256GCM"
	case X448_SHA512_AES256GCM:
		return "X448_SHA512_AES256GCM"
	}

	return "UknownCiphersuite"
}

type cipherConstants struct {
	KeySize    int
	NonceSize  int
	SecretSize int
	HPKEKEM    hpke.KEMID
	HPKEKDF    hpke.KDFID
	HPKEAEAD   hpke.AEADID
}

func (cs CipherSuite) constants() cipherConstants {
	switch cs {
	case P256_SHA256_AES128GCM:
		return cipherConstants{16, 12, 32, hpke.DHKEM_P256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128}
	case X25519_SHA256_AES128GCM:
		return cipherConstants{16, 12, 32, hpke.DHKEM_X25519, hpke.KDF_HKDF_SHA256, hpke.AEAD_AESGCM128}
	case P521_SHA512_AES256GCM:
		return cipherConstants{32, 12, 64, hpke.DHKEM_P521, hpke.KDF_HKDF_SHA512, hpke.AEAD_AESGCM256}
	case X448_SHA512_AES256GCM:
		return cipherConstants{32, 12, 64, hpke.DHKEM_X448, hpke.KDF_HKDF_SHA512, hpke.AEAD_AESGCM256}
	}

	panic("Unsupported ciphersuite")
}

func (cs CipherSuite) newDigest() hash.Hash {
	switch cs {
	case P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM:
		return sha256.New()

	case P521_SHA512_AES256GCM, X448_SHA512_AES256GCM:
		return sha512.New()
	}

	panic("Unsupported ciphersuite")
}

func (cs CipherSuite) digest(data []byte) []byte {
	d := cs.newDigest()
	d.Write(data)
	return d.Sum(nil)
}

func (cs CipherSuite) newHMAC(key []byte) hash.Hash {
	return hmac.New(cs.newDigest, key)
}

func (cs CipherSuite) newAEAD(key []byte) (cipher.AEAD, error) {
	switch cs {
	case P256_SHA256_AES128GCM, P521_SHA512_AES256GCM:
		fallthrough
	case X25519_SHA256_AES128GCM, X448_SHA512_AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		return cipher.NewGCM(block)
	}

	panic("Unsupported ciphersuite")
}

func (cs CipherSuite) hkdfExtract(salt, ikm []byte) []byte {
	mac := cs.newHMAC(salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func (cs CipherSuite) hkdfExpand(secret, info []byte, size int) []byte {
	if size > cs.constants().SecretSize {
		panic("Requested size too large for HKDF-Expand")
	}

	infoAndCounter := append(info, 0x01)
	mac := cs.newHMAC(secret)
	mac.Write(infoAndCounter)
	val := mac.Sum(nil)[:size]
	return val
}

type hkdfLabel struct {
	Length  uint16
	Label   []byte `tls:"head=1"`
	Context []byte `tls:"head=4"`
}

func (cs CipherSuite) hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	mlsLabel := []byte("mls10 " + label)
	labelData, err := syntax.Marshal(hkdfLabel{uint16(length), mlsLabel, context})
	if err != nil {
		panic(fmt.Errorf("Error marshaling HKDF label: %v", err))
	}
	return cs.hkdfExpand(secret, labelData, length)
}

func (cs CipherSuite) deriveSecret(secret []byte, label string, context []byte) []byte {
	contextHash := cs.digest(context)
	size := cs.constants().SecretSize
	return cs.hkdfExpandLabel(secret, label, contextHash, size)
}

type applicationContext struct {
	Node       nodeIndex
	Generation uint32
}

func (cs CipherSuite) deriveAppSecret(secret []byte, label string, node nodeIndex, generation uint32, length int) []byte {
	ctx, err := syntax.Marshal(applicationContext{node, generation})
	if err != nil {
		panic(fmt.Errorf("Error marshaling application context: %v", err))
	}

	return cs.hkdfExpandLabel(secret, label, ctx, length)
}

func (cs CipherSuite) hpke() hpkeInstance {
	cc := cs.constants()
	suite, err := hpke.AssembleCipherSuite(cc.HPKEKEM, cc.HPKEKDF, cc.HPKEAEAD)
	if err != nil {
		panic("Unable to construct HPKE ciphersuite")
	}

	return hpkeInstance{cs, suite}
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

func (k *HPKEPublicKey) equals(o *HPKEPublicKey) bool {
	return bytes.Equal(k.Data, o.Data)
}

type HPKECiphertext struct {
	KEMOutput  []byte `tls:"head=2"`
	Ciphertext []byte `tls:"head=4"`
}

type hpkeInstance struct {
	BaseSuite CipherSuite
	Suite     hpke.CipherSuite
}

func (h hpkeInstance) Generate() (HPKEPrivateKey, error) {
	priv, pub, err := h.Suite.KEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		return HPKEPrivateKey{}, err
	}

	key := HPKEPrivateKey{
		Data:      h.Suite.KEM.MarshalPrivate(priv),
		PublicKey: HPKEPublicKey{h.Suite.KEM.Marshal(pub)},
	}
	return key, nil
}

func (h hpkeInstance) Derive(seed []byte) (HPKEPrivateKey, error) {
	digest := h.BaseSuite.digest(seed)

	var priv hpke.KEMPrivateKey
	var err error
	switch h.BaseSuite.constants().HPKEKEM {
	case hpke.DHKEM_P256, hpke.DHKEM_P521, hpke.DHKEM_X25519:
		priv, err = h.Suite.KEM.UnmarshalPrivate(digest)
	case hpke.DHKEM_X448:
		priv, err = h.Suite.KEM.UnmarshalPrivate(digest[:56])
	}

	if err != nil {
		return HPKEPrivateKey{}, err
	}

	pub := priv.PublicKey()
	key := HPKEPrivateKey{
		Data:      h.Suite.KEM.MarshalPrivate(priv),
		PublicKey: HPKEPublicKey{h.Suite.KEM.Marshal(pub)},
	}
	return key, nil
}

func (h hpkeInstance) Encrypt(pub HPKEPublicKey, aad, pt []byte) (HPKECiphertext, error) {
	pkR, err := h.Suite.KEM.Unmarshal(pub.Data)
	if err != nil {
		return HPKECiphertext{}, err
	}

	enc, ctx, err := hpke.SetupBaseI(h.Suite, rand.Reader, pkR, nil)
	if err != nil {
		return HPKECiphertext{}, err
	}

	ct := ctx.Seal(aad, pt)
	return HPKECiphertext{enc, ct}, nil
}

func (h hpkeInstance) Decrypt(priv HPKEPrivateKey, aad []byte, ct HPKECiphertext) ([]byte, error) {
	skR, err := h.Suite.KEM.UnmarshalPrivate(priv.Data)
	if err != nil {
		return nil, err
	}

	ctx, err := hpke.SetupBaseR(h.Suite, skR, ct.KEMOutput, nil)
	if err != nil {
		return nil, err
	}

	return ctx.Open(aad, ct.Ciphertext)
}

///
/// Signing
///

type SignaturePrivateKey struct {
	Data      []byte `tls:"head=2"`
	PublicKey SignaturePublicKey
}

type SignaturePublicKey struct {
	Data []byte `tls:"head=2"`
}

type SignatureScheme uint16

const (
	ECDSA_SECP256R1_SHA256 SignatureScheme = 0x0403
	Ed25519                SignatureScheme = 0x0807
)

func (ss SignatureScheme) supported() bool {
	switch ss {
	case ECDSA_SECP256R1_SHA256, Ed25519:
		return true
	}

	return false
}

func (ss SignatureScheme) String() string {
	switch ss {
	case ECDSA_SECP256R1_SHA256:
		return "ECDSA_SECP256R1_SHA256"
	case Ed25519:
		return "Ed25519"
	}

	return "UnknownSignatureScheme"
}

func (ss SignatureScheme) Derive(preSeed []byte) (SignaturePrivateKey, error) {
	switch ss {
	case ECDSA_SECP256R1_SHA256:
		h := sha256.New()
		h.Write(preSeed)
		priv := h.Sum(nil)

		curve := elliptic.P256()
		x, y := curve.Params().ScalarBaseMult(priv)
		pub := elliptic.Marshal(curve, x, y)
		key := SignaturePrivateKey{
			Data:      priv,
			PublicKey: SignaturePublicKey{pub},
		}
		return key, nil

	case Ed25519:
		h := sha256.New()
		h.Write(preSeed)
		seed := h.Sum(nil)
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		key := SignaturePrivateKey{
			Data:      priv,
			PublicKey: SignaturePublicKey{pub},
		}
		return key, nil
	}
	panic("Unsupported algorithm")
}

func (ss SignatureScheme) Generate() (SignaturePrivateKey, error) {
	switch ss {
	case ECDSA_SECP256R1_SHA256:
		curve := elliptic.P256()
		priv, x, y, err := elliptic.GenerateKey(curve, rand.Reader)
		if err != nil {
			return SignaturePrivateKey{}, err
		}

		pub := elliptic.Marshal(curve, x, y)
		key := SignaturePrivateKey{
			Data:      priv,
			PublicKey: SignaturePublicKey{pub},
		}
		return key, nil

	case Ed25519:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return SignaturePrivateKey{}, err
		}

		key := SignaturePrivateKey{
			Data:      priv,
			PublicKey: SignaturePublicKey{pub},
		}
		return key, nil
	}
	panic("Unsupported algorithm")
}

type ecdsaSignature struct {
	R, S *big.Int
}

func (ss SignatureScheme) Sign(priv *SignaturePrivateKey, message []byte) ([]byte, error) {
	switch ss {
	case ECDSA_SECP256R1_SHA256:
		h := sha256.New()
		h.Write(message)
		digest := h.Sum(nil)

		ecPriv := &ecdsa.PrivateKey{
			D: big.NewInt(0).SetBytes(priv.Data),
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
			},
		}
		return ecPriv.Sign(rand.Reader, digest, nil)

	case Ed25519:
		priv25519 := ed25519.PrivateKey(priv.Data)
		return ed25519.Sign(priv25519, message), nil
	}
	panic("Unsupported algorithm")
}

func (ss SignatureScheme) Verify(pub *SignaturePublicKey, message, signature []byte) bool {
	switch ss {
	case ECDSA_SECP256R1_SHA256:
		h := sha256.New()
		h.Write(message)
		digest := h.Sum(nil)

		curve := elliptic.P256()
		x, y := elliptic.Unmarshal(curve, pub.Data)

		var sig ecdsaSignature
		_, err := asn1.Unmarshal(signature, &sig)
		if err != nil {
			return false
		}

		ecPub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		return ecdsa.Verify(ecPub, digest, sig.R, sig.S)

	case Ed25519:
		pub25519 := ed25519.PublicKey(pub.Data)
		return ed25519.Verify(pub25519, message, signature)
	}
	panic("Unsupported algorithm")
}
