package mls

import (
	"bytes"
	"testing"

	"github.com/bifurcation/mint/syntax"
	"github.com/stretchr/testify/require"
)

var supportedSuites = []CipherSuite{
	X25519_AES128GCM_SHA256_Ed25519,
	P256_AES128GCM_SHA256_P256,
	P521_AES256GCM_SHA512_P521,
}

var supportedSchemes = []SignatureScheme{
	ECDSA_SECP256R1_SHA256,
	Ed25519,
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
		case X25519_AES128GCM_SHA256_Ed25519, P256_AES128GCM_SHA256_P256:
			out = out256
		case P521_AES256GCM_SHA512_P521:
			out = out512
		}

		d := suite.digest(in)
		require.Equal(t, d, out)
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

	encryptDecrypt := func(suite CipherSuite) func(t *testing.T) {
		return func(t *testing.T) {
			var key, nonce, aad, pt, ct []byte
			switch suite {
			case X25519_AES128GCM_SHA256_Ed25519, P256_AES128GCM_SHA256_P256:
				key, nonce, aad, pt, ct = key128, nonce128, aad128, pt128, ct128
			case P521_AES256GCM_SHA512_P521:
				key, nonce, aad, pt, ct = key256, nonce256, aad256, pt256, ct256
			}

			aead, err := suite.newAEAD(key)
			require.Nil(t, err)

			// Test encryption
			encrypted := aead.Seal(nil, nonce, pt, aad)
			require.Equal(t, ct, encrypted)

			// Test decryption
			decrypted, err := aead.Open(nil, nonce, ct, aad)
			require.Nil(t, err)
			require.Equal(t, pt, decrypted)
		}
	}

	for _, suite := range supportedSuites {
		t.Run("todo" /*suite.String()*/, encryptDecrypt(suite))
	}
}

func TestHPKE(t *testing.T) {
	aad := []byte("doo-bee-doo")
	original := []byte("Attack at dawn!")
	seed := []byte("All the flowers of tomorrow are in the seeds of today")

	encryptDecrypt := func(suite CipherSuite) func(t *testing.T) {
		return func(t *testing.T) {
			priv, err := suite.hpke().Generate()
			require.Nil(t, err)

			priv, err = suite.hpke().Derive(seed)
			require.Nil(t, err)

			encrypted, err := suite.hpke().Encrypt(priv.PublicKey, aad, original)
			require.Nil(t, err)

			decrypted, err := suite.hpke().Decrypt(priv, aad, encrypted)
			require.Nil(t, err)
			require.Equal(t, original, decrypted)
		}
	}

	for _, suite := range supportedSuites {
		t.Run("todo" /*suite.String()*/, encryptDecrypt(suite))
	}
}

func TestSignVerify(t *testing.T) {
	message := []byte("I promise Suhas five dollars")
	seed := []byte("All the flowers of tomorrow are in the seeds of today")

	signVerify := func(scheme SignatureScheme) func(t *testing.T) {
		return func(t *testing.T) {
			priv, err := scheme.Generate()
			require.Nil(t, err)

			priv, err = scheme.Derive(seed)
			require.Nil(t, err)

			signature, err := scheme.Sign(&priv, message)
			require.Nil(t, err)

			verified := scheme.Verify(&priv.PublicKey, message, signature)
			require.True(t, verified)
		}
	}

	for _, scheme := range supportedSchemes {
		t.Run(scheme.String(), signVerify(scheme))
	}
}

///
/// Test Vectors
///

type CryptoTestCase struct {
	CipherSuite      CipherSuite
	HKDFExtractOut   []byte `tls:"head=1"`
	DeriveKeyPairPub HPKEPublicKey
	HPKEOut          HPKECiphertext
}

type CryptoTestVectors struct {
	HKDFExtractSalt   []byte           `tls:"head=1"`
	HKDFExtractIKM    []byte           `tls:"head=1"`
	DeriveKeyPairSeed []byte           `tls:"head=1"`
	HPKEAAD           []byte           `tls:"head=1"`
	HPKEPlaintext     []byte           `tls:"head=1"`
	Cases             []CryptoTestCase `tls:"head=4"`
}

func generateCryptoVectors(t *testing.T) []byte {
	tv := CryptoTestVectors{
		HKDFExtractSalt:   []byte{0, 1, 2, 3},
		HKDFExtractIKM:    []byte{4, 5, 6, 7},
		DeriveKeyPairSeed: []byte{0, 1, 2, 3},
		HPKEAAD:           bytes.Repeat([]byte{0xB1}, 128),
		HPKEPlaintext:     bytes.Repeat([]byte{0xB2}, 128),
		Cases: []CryptoTestCase{
			{CipherSuite: X25519_AES128GCM_SHA256_Ed25519},
			{CipherSuite: P256_AES128GCM_SHA256_P256},
		},
	}

	var err error
	for i := range tv.Cases {
		tc := &tv.Cases[i]

		tc.HKDFExtractOut = tc.CipherSuite.hkdfExtract(tv.HKDFExtractSalt, tv.HKDFExtractIKM)

		priv, err = tc.CipherSuite.hpke().Derive(tv.DeriveKeyPairSeed)
		tc.DeriveKeyPairPub = priv.PublicKey
		require.Nil(t, err)

		tc.HPKEOut, err = tc.CipherSuite.hpke().Encrypt(tc.DeriveKeyPairPub, tv.HPKEAAD, tv.HPKEPlaintext)
		require.Nil(t, err)
	}

	vec, err := syntax.Marshal(tv)
	require.Nil(t, err)
	return vec
}

func verifyCryptoVectors(t *testing.T, data []byte) {
	var tv CryptoTestVectors
	_, err := syntax.Unmarshal(data, &tv)
	require.Nil(t, err)

	for _, tc := range tv.Cases {
		hkdfExtractOut := tc.CipherSuite.hkdfExtract(tv.HKDFExtractSalt, tv.HKDFExtractIKM)
		require.Equal(t, hkdfExtractOut, tc.HKDFExtractOut)

		priv, err = tc.CipherSuite.hpke().Derive(tv.DeriveKeyPairSeed)
		require.Nil(t, err)
		require.Equal(t, priv.PublicKey.Data, tc.DeriveKeyPairPub.Data)

		plaintext, err := tc.CipherSuite.hpke().Decrypt(priv, tv.HPKEAAD, tc.HPKEOut)
		require.Nil(t, err)
		require.Equal(t, plaintext, tv.HPKEPlaintext)
	}
}
