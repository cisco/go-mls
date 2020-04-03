package mls

import (
	"github.com/bifurcation/mint/syntax"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBasicCredential(t *testing.T) {
	identity := []byte("res ipsa")
	scheme := Ed25519
	priv, err := scheme.Generate()
	require.Nil(t, err)

	cred := NewBasicCredential(identity, scheme, &priv)
	require.True(t, cred.Equals(*cred))
	require.Equal(t, cred.Type(), CredentialTypeBasic)
	require.Equal(t, cred.Scheme(), scheme)
	require.Equal(t, *cred.PublicKey(), priv.PublicKey)
}

func TestCredentialErrorCases(t *testing.T) {
	cred := Credential{nil, nil}

	require.False(t, cred.Equals(cred))
	require.Equal(t, cred.Type(), CredentialTypeInvalid)
	require.Nil(t, cred.PublicKey())
	require.Equal(t, cred.Scheme(), SIGNATURE_SCHEME_UNKNOWN)
	_, err := syntax.Marshal(cred)
	require.NotNil(t, err)

}

func TestBasicCredentialExportApi(t *testing.T) {
	identity := []byte("res ipsa")
	scheme := Ed25519
	priv, err := scheme.Generate()
	require.Nil(t, err)

	cred := NewBasicCredential(identity, scheme, &priv)
	priv, ok := cred.PrivateKey()
	require.True(t, ok)
	require.NotEmpty(t, priv)


	// remove sensitive info before exporting
	cred.RemovePrivateKey()
	require.Nil(t, cred.privateKey)

	priv, ok = cred.PrivateKey()
	require.False(t, ok)
	require.Empty(t, priv)
}