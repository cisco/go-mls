package mls

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func unhex(s string) []byte {
	d, _ := hex.DecodeString(s)
	return d
}

var supportedSuites = []CipherSuite{
	P256_SHA256_AES128GCM,
	P521_SHA512_AES256GCM,
	X25519_SHA256_AES128GCM,
	X448_SHA512_AES256GCM,
}

func TestDigest(t *testing.T) {
	in := unhex("6162636462636465636465666465666765666768666768696768696a68696a6b6" +
		"96a6b6c6a6b6c6d6b6c6d6e6c6d6e6f6d6e6f706e6f7071")
	out256 := unhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
	out512 := unhex("204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c3359" +
		"6fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445")

	for _, suite := range supportedSuites {
		var out []byte
		switch suite {
		case P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM:
			out = out256
		case P521_SHA512_AES256GCM, X448_SHA512_AES256GCM:
			out = out512
		}

		d := suite.digest(in)
		if !bytes.Equal(d, out) {
			t.Fatalf("Incorrect digest: %x != %x", d, out)
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	// AES-GCM
	// https://tools.ietf.org/html/draft-mcgrew-gcm-test-01#section-4
	key128 := unhex("4c80cdefbb5d10da906ac73c3613a634")
	nonce128 := unhex("2e443b684956ed7e3b244cfe")
	aad128 := unhex("000043218765432100000000")
	pt128 := unhex("45000048699a000080114db7c0a80102c0a801010a9bf15638d3010000010000" +
		"00000000045f736970045f756470037369700963796265726369747902646b00" +
		"0021000101020201")
	ct128 := unhex("fecf537e729d5b07dc30df528dd22b768d1b98736696a6fd348509fa13ceac34" +
		"cfa2436f14a3f3cf65925bf1f4a13c5d15b21e1884f5ff6247aeabb786b93bce" +
		"61bc17d768fd9732459018148f6cbe722fd04796562dfdb4")

	key256 := unhex("abbccddef00112233445566778899aababbccddef00112233445566778899aab")
	nonce256 := unhex("112233440102030405060708")
	aad256 := unhex("4a2cbfe300000002")
	pt256 := unhex("4500003069a6400080062690c0a801029389155e0a9e008b2dc57ee000000000" +
		"7002400020bf0000020405b40101040201020201")
	ct256 := unhex("ff425c9b724599df7a3bcd510194e00d6a78107f1b0b1cbf06efae9d65a5d763" +
		"748a637985771d347f0545659f14e99def842d8eb335f4eecfdbf831824b4c49" +
		"15956c96")

	for _, suite := range supportedSuites {
		var key, nonce, aad, pt, ct []byte
		switch suite {
		case P256_SHA256_AES128GCM, X25519_SHA256_AES128GCM:
			key, nonce, aad, pt, ct = key128, nonce128, aad128, pt128, ct128
		case P521_SHA512_AES256GCM, X448_SHA512_AES256GCM:
			key, nonce, aad, pt, ct = key256, nonce256, aad256, pt256, ct256
		}

		aead, err := suite.newAEAD(key)
		if err != nil {
			t.Fatalf("Error creating AEAD: %v", err)
		}

		// Test encryption
		encrypted := aead.Seal(nil, nonce, pt, aad)
		if !bytes.Equal(ct, encrypted) {
			t.Fatalf("Incorrect encryption: %x != %x", ct, encrypted)
		}

		// Test decryption
		decrypted, err := aead.Open(nil, nonce, ct, aad)
		if err != nil {
			t.Fatalf("Error in decryption: %v", err)
		}
		if !bytes.Equal(pt, decrypted) {
			t.Fatalf("Incorrect decryption: %x != %x", pt, decrypted)
		}
	}
}
