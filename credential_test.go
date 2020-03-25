package mls

import (
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
	cred0 := Credential{nil, nil}

	require.True(t, !cred0.Equals(cred0))
	require.Equal(t, cred0.Type(), CredentialTypeInvalid)
	require.Panics(t, func() { cred0.PublicKey() })
	require.Panics(t, func() { cred0.Scheme() })

	_, err := cred0.MarshalTLS()
	require.Error(t, err)
}
