package mls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func testAllCiphersuites(t *testing.T, f func(id CiphersuiteID, t *testing.T)) {
	for _, id := range AllSupportedCiphersuites {
		t.Run(id.String(), func(t *testing.T) { f(id, t) })
	}
}

func TestDerive(t *testing.T) {
	// TODO Known-answer tests for:
	// * ExpandWithLabel
	// * DeriveSecret
	// * DeriveTreeSecret
}

func TestHPKE(t *testing.T) {
	roundTrip := func(id CiphersuiteID, t *testing.T) {
		cs, err := NewCiphersuite(id)
		require.NoError(t, err)

		priv, err := cs.DeriveHPKE([]byte("test"))
		require.NoError(t, err)

		aad := []byte("aad")
		original := []byte("message")
		encrypted, err := cs.EncryptHPKE(priv.PublicKey, aad, original)
		require.NoError(t, err)

		decrypted, err := cs.DecryptHPKE(priv, aad, encrypted)
		require.NoError(t, err)
		require.Equal(t, original, decrypted)
	}

	testAllCiphersuites(t, roundTrip)
}

func TestSignature(t *testing.T) {
	roundTrip := func(id CiphersuiteID, t *testing.T) {
		cs, err := NewCiphersuite(id)
		require.NoError(t, err)

		priv, err := cs.DeriveSignature([]byte("test"))
		require.NoError(t, err)

		message := []byte("message")
		signature, err := cs.Sign(priv, message)
		require.NoError(t, err)

		verified := cs.Verify(priv.PublicKey, message, signature)
		require.True(t, verified)
	}

	testAllCiphersuites(t, roundTrip)
}
