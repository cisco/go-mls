package mls

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
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

func (cs CipherSuite) Supported() bool {
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

func (cs CipherSuite) NewDigest() hash.Hash {
	switch cs {
	case P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM:
		return sha256.New()

	case P521_SHA512_AES256GCM, X448_SHA512_AES256GCM:
		return sha512.New()
	}

	panic("Unsupported ciphersuite")
}

func (cs CipherSuite) NewHMAC(key []byte) hash.Hash {
	return hmac.New(cs.NewDigest, key)
}

func (cs CipherSuite) NewAEAD(key []byte) (cipher.AEAD, error) {
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

func (cs CipherSuite) HKDFExtract(salt, ikm []byte) []byte {
	mac := cs.NewHMAC(salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

func (cs CipherSuite) hkdfExpand(secret, info []byte, size int) []byte {
	if size > cs.constants().SecretSize {
		panic("Requested size too large for HKDF-Expand")
	}

	infoAndCounter := append(info, 0x01)
	mac := cs.NewHMAC(secret)
	mac.Write(infoAndCounter)
	return mac.Sum(nil)[:size]
}

type hkdfLabel struct {
	Length  uint16
	Label   []byte `tls:"head=1"`
	Context []byte `tls:"head=4"`
}

func (cs CipherSuite) HKDFExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	label_data, err := syntax.Marshal(hkdfLabel{uint16(length), []byte(label), context})
	if err != nil {
		panic(fmt.Errorf("Error marshaling HKDF label: %v", err))
	}

	return cs.hkdfExpand(secret, label_data, length)
}
