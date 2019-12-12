package mls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

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

type cipherConstants struct {
	KeySize    int
	NonceSize  int
	SecretSize int
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
