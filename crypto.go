package mls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/bifurcation/mint/syntax"
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

type cipherConstants struct {
	KeySize    int
	NonceSize  int
	SecretSize int
	HPKEKDF    hpke.KDFID
	HPKEAEAD   hpke.AEADID
	HPKEMAC    hpke.MACID
}

func (cs CipherSuite) constants() cipherConstants {
	switch cs {
	case P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM:
		return cipherConstants{16, 12, 32}
	case P521_SHA512_AES256GCM, X448_SHA512_AES256GCM:
		return cipherConstants{32, 12, 64}
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
	return mac.Sum(nil)[:size]
}

type hkdfLabel struct {
	Length  uint16
	Label   []byte `tls:"head=1"`
	Context []byte `tls:"head=4"`
}

func (cs CipherSuite) hkdfExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	label_data, err := syntax.Marshal(hkdfLabel{uint16(length), []byte(label), context})
	if err != nil {
		panic(fmt.Errorf("Error marshaling HKDF label: %v", err))
	}

	return cs.hkdfExpand(secret, label_data, length)
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

///
/// HPKE
///

// TODO

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

func (ss SignatureScheme) Supported() bool {
	switch ss {
	case ECDSA_SECP256R1_SHA256, Ed25519:
		return true
	}

	return false
}

func (ss SignatureScheme) Generate() (SignaturePrivateKey, error) {
	switch ss {
	case ECDSA_SECP256R1_SHA256:
		// TODO

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

func (ss SignatureScheme) Sign(priv SignaturePrivateKey, message []byte) []byte {
	switch ss {
	case ECDSA_SECP256R1_SHA256:
		// TODO

	case Ed25519:
		priv25519 := ed25519.PrivateKey(priv.Data)
		return ed25519.Sign(priv25519, message)
	}
	panic("Unsupported algorithm")
}

func (ss SignatureScheme) Verify(pub SignaturePublicKey, message, signature []byte) bool {
	switch ss {
	case ECDSA_SECP256R1_SHA256:
		// TODO

	case Ed25519:
		pub25519 := ed25519.PublicKey(pub.Data)
		return ed25519.Verify(pub25519, message, signature)
	}
	panic("Unsupported algorithm")
}
