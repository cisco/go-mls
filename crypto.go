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

	"github.com/cisco/go-hpke"
	"github.com/cisco/go-tls-syntax"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ed25519"
)

type CipherSuite uint16

const (
	X25519_AES128GCM_SHA256_Ed25519        CipherSuite = 0x0001
	P256_AES128GCM_SHA256_P256             CipherSuite = 0x0002
	X25519_CHACHA20POLY1305_SHA256_Ed25519 CipherSuite = 0x0003
	X448_AES256GCM_SHA512_Ed448            CipherSuite = 0x0004 // UNSUPPORTED
	P521_AES256GCM_SHA512_P521             CipherSuite = 0x0005
	X448_CHACHA20POLY1305_SHA512_Ed448     CipherSuite = 0x0006 // UNSUPPORTED
)

func (cs CipherSuite) supported() bool {
	switch cs {
	case X25519_AES128GCM_SHA256_Ed25519,
		P256_AES128GCM_SHA256_P256,
		P521_AES256GCM_SHA512_P521,
		X25519_CHACHA20POLY1305_SHA256_Ed25519:
		return true
	}

	return false
}

func (cs CipherSuite) String() string {
	switch cs {
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

	return "UnknownCipherSuite"
}

type cipherConstants struct {
	KeySize    int
	NonceSize  int
	SecretSize int
	HPKEKEM    hpke.KEMID
	HPKEKDF    hpke.KDFID
	HPKEAEAD   hpke.AEADID
}

func (cs CipherSuite) Constants() cipherConstants {
	switch cs {
	case X25519_AES128GCM_SHA256_Ed25519:
		return cipherConstants{
			KeySize:    16,
			NonceSize:  12,
			SecretSize: 32,
			HPKEKEM:    hpke.DHKEM_X25519,
			HPKEKDF:    hpke.KDF_HKDF_SHA256,
			HPKEAEAD:   hpke.AEAD_AESGCM128,
		}
	case P256_AES128GCM_SHA256_P256:
		return cipherConstants{
			KeySize:    16,
			NonceSize:  12,
			SecretSize: 32,
			HPKEKEM:    hpke.DHKEM_P256,
			HPKEKDF:    hpke.KDF_HKDF_SHA256,
			HPKEAEAD:   hpke.AEAD_AESGCM128,
		}
	case X25519_CHACHA20POLY1305_SHA256_Ed25519:
		return cipherConstants{
			KeySize:    32,
			NonceSize:  12,
			SecretSize: 32,
			HPKEKEM:    hpke.DHKEM_X25519,
			HPKEKDF:    hpke.KDF_HKDF_SHA256,
			HPKEAEAD:   hpke.AEAD_CHACHA20POLY1305,
		}
	case P521_AES256GCM_SHA512_P521:
		return cipherConstants{
			KeySize:    32,
			NonceSize:  12,
			SecretSize: 64,
			HPKEKEM:    hpke.DHKEM_P521,
			HPKEKDF:    hpke.KDF_HKDF_SHA512,
			HPKEAEAD:   hpke.AEAD_AESGCM256,
		}
	}

	panic("Unsupported ciphersuite")
}

func (cs CipherSuite) Scheme() SignatureScheme {
	switch cs {
	case X25519_AES128GCM_SHA256_Ed25519:
		return Ed25519
	case P256_AES128GCM_SHA256_P256:
		return ECDSA_SECP256R1_SHA256
	case X25519_CHACHA20POLY1305_SHA256_Ed25519:
		return Ed25519
	case P521_AES256GCM_SHA512_P521:
		return ECDSA_SECP521R1_SHA512
	}

	panic("Unsupported ciphersuite")
}

func (cs CipherSuite) zero() []byte {
	return bytes.Repeat([]byte{0x00}, cs.newDigest().Size())
}

func (cs CipherSuite) newDigest() hash.Hash {
	switch cs {
	case X25519_AES128GCM_SHA256_Ed25519, P256_AES128GCM_SHA256_P256,
		X25519_CHACHA20POLY1305_SHA256_Ed25519:
		return sha256.New()

	case X448_AES256GCM_SHA512_Ed448, P521_AES256GCM_SHA512_P521:
		return sha512.New()
	}

	panic("Unsupported ciphersuite")
}

func (cs CipherSuite) Digest(data []byte) []byte {
	d := cs.newDigest()
	d.Write(data)
	return d.Sum(nil)
}

func (cs CipherSuite) NewHMAC(key []byte) hash.Hash {
	return hmac.New(cs.newDigest, key)
}

func (cs CipherSuite) NewAEAD(key []byte) (cipher.AEAD, error) {
	switch cs {
	case X25519_AES128GCM_SHA256_Ed25519, P256_AES128GCM_SHA256_P256:
		fallthrough
	case X448_AES256GCM_SHA512_Ed448, P521_AES256GCM_SHA512_P521:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}

		return cipher.NewGCM(block)
	case X25519_CHACHA20POLY1305_SHA256_Ed25519:
		return chacha20poly1305.New(key)
	}

	panic("Unsupported ciphersuite")
}

func (cs CipherSuite) hkdfExtract(salt, ikm []byte) []byte {
	mac := cs.NewHMAC(salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func (cs CipherSuite) hkdfExpand(secret, info []byte, size int) []byte {
	last := []byte{}
	buf := []byte{}
	counter := byte(1)
	for len(buf) < size {
		mac := cs.NewHMAC(secret)
		mac.Write(last)
		mac.Write(info)
		mac.Write([]byte{counter})

		last = mac.Sum(nil)
		counter += 1
		buf = append(buf, last...)
	}
	return buf[:size]
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
	contextHash := cs.Digest(context)
	size := cs.Constants().SecretSize
	return cs.hkdfExpandLabel(secret, label, contextHash, size)
}

type applicationContext struct {
	Node       NodeIndex
	Generation uint32
}

func (cs CipherSuite) deriveAppSecret(secret []byte, label string, node NodeIndex, generation uint32, length int) []byte {
	ctx, err := syntax.Marshal(applicationContext{node, generation})
	if err != nil {
		panic(fmt.Errorf("Error marshaling application context: %v", err))
	}

	return cs.hkdfExpandLabel(secret, label, ctx, length)
}

func (cs CipherSuite) hpke() HPKEInstance {
	cc := cs.Constants()
	suite, err := hpke.AssembleCipherSuite(cc.HPKEKEM, cc.HPKEKDF, cc.HPKEAEAD)
	if err != nil {
		panic("Unable to construct HPKE ciphersuite")
	}

	return HPKEInstance{cs, suite}
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
	Ciphertext []byte `tls:"head=4"`
}

type HPKEInstance struct {
	BaseSuite CipherSuite
	Suite     hpke.CipherSuite
}

func (h HPKEInstance) Generate() (HPKEPrivateKey, error) {
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

func (h HPKEInstance) Derive(seed []byte) (HPKEPrivateKey, error) {
	keyPairSecretSize := 0
	switch h.BaseSuite.Constants().HPKEKEM {
	case hpke.DHKEM_X25519:
		keyPairSecretSize = 32
	case hpke.DHKEM_P256:
		keyPairSecretSize = 32
	case hpke.DHKEM_P521:
		keyPairSecretSize = 66
	case hpke.DHKEM_X448:
		keyPairSecretSize = 56
	}

	cs := h.BaseSuite
	keyPairSecret := cs.hkdfExpandLabel(seed, "key pair", []byte{}, keyPairSecretSize)

	var priv hpke.KEMPrivateKey
	var err error
	switch h.BaseSuite.Constants().HPKEKEM {
	case hpke.DHKEM_P256, hpke.DHKEM_P521, hpke.DHKEM_X25519:
		priv, err = h.Suite.KEM.UnmarshalPrivate(keyPairSecret)
	case hpke.DHKEM_X448:
		priv, err = h.Suite.KEM.UnmarshalPrivate(keyPairSecret)
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

func (h HPKEInstance) Encrypt(pub HPKEPublicKey, aad, pt []byte) (HPKECiphertext, error) {
	pkR, err := h.Suite.KEM.Unmarshal(pub.Data)
	if err != nil {
		return HPKECiphertext{}, err
	}

	enc, ctx, err := hpke.SetupBaseS(h.Suite, rand.Reader, pkR, nil)
	if err != nil {
		return HPKECiphertext{}, err
	}

	ct := ctx.Seal(aad, pt)
	return HPKECiphertext{enc, ct}, nil
}

func (h HPKEInstance) Decrypt(priv HPKEPrivateKey, aad []byte, ct HPKECiphertext) ([]byte, error) {
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

func (pub SignaturePublicKey) Equals(other SignaturePublicKey) bool {
	return bytes.Equal(pub.Data, other.Data)
}

type SignatureScheme uint16

const (
	ECDSA_SECP256R1_SHA256 SignatureScheme = 0x0403
	ECDSA_SECP521R1_SHA512 SignatureScheme = 0x0603
	Ed25519                SignatureScheme = 0x0807
)

func (ss SignatureScheme) supported() bool {
	switch ss {
	case ECDSA_SECP256R1_SHA256, ECDSA_SECP521R1_SHA512, Ed25519:
		return true
	}

	return false
}

func (ss SignatureScheme) String() string {
	switch ss {
	case ECDSA_SECP256R1_SHA256:
		return "ECDSA_SECP256R1_SHA256"
	case ECDSA_SECP521R1_SHA512:
		return "ECDSA_SECP521R1_SHA512"
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

	case ECDSA_SECP521R1_SHA512:
		h := sha512.New()
		h.Write(preSeed)
		priv := h.Sum(nil)

		curve := elliptic.P521()
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

	case ECDSA_SECP521R1_SHA512:
		curve := elliptic.P521()
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

	case ECDSA_SECP521R1_SHA512:
		h := sha512.New()
		h.Write(message)
		digest := h.Sum(nil)

		ecPriv := &ecdsa.PrivateKey{
			D: big.NewInt(0).SetBytes(priv.Data),
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P521(),
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

	case ECDSA_SECP521R1_SHA512:
		h := sha512.New()
		h.Write(message)
		digest := h.Sum(nil)

		curve := elliptic.P521()
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
