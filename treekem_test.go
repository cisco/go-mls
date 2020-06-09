package mls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func newKeyPackage(t *testing.T) ([]byte, SignaturePrivateKey, *KeyPackage) {
	secret := randomBytes(32)

	initPriv, err := suite.hpke().Derive(secret)
	require.Nil(t, err)

	sigPriv, err := suite.Scheme().Derive(secret)
	require.Nil(t, err)

	cred := NewBasicCredential(userID, suite.Scheme(), &sigPriv)

	kp, err := NewKeyPackageWithInitKey(suite, initPriv, cred)

	return secret, sigPriv, kp
}

func TestTreeKEM(t *testing.T) {
	context := randomBytes(32)

	// Make a new one-person pub + priv
	pub := NewTreeKEMPublicKey(suite)

	// AddLeaf + Encap + Merge
	secretA, sigPrivA, kpA := newKeyPackage(t)

	indexA := pub.AddLeaf(*kpA)
	require.Equal(t, indexA, LeafIndex(0))

	privA, err := NewTreeKEMPrivateKey(suite, pub.Size(), indexA, secretA)
	require.Nil(t, err)
	require.True(t, privA.Consistent(*pub))

	leafA := randomBytes(32)
	privA, path, err := pub.Encap(indexA, context, leafA, sigPrivA, nil)
	require.Nil(t, err)

	err = pub.Merge(indexA, *path)
	require.Nil(t, err)
	require.True(t, privA.Consistent(*pub))

	// AddLeaf + Encap + Decap + Merge
	secretB, sigPrivB, kpB := newKeyPackage(t)

	indexB := pub.AddLeaf(*kpB)
	require.Equal(t, indexB, LeafIndex(1))

	// Add B
	leafA = randomBytes(32)
	privA, path, err = pub.Encap(indexA, context, leafA, sigPrivA, nil)
	require.Nil(t, err)

	err = pub.Merge(indexA, *path)
	require.Nil(t, err)
	require.True(t, privA.Consistent(*pub))

	overlapAB, pathSecretB, err := privA.PathSecret(indexB)
	require.Nil(t, err)

	privB, err := NewTreeKEMPrivateKeyForJoiner(suite, indexB, pub.Size(), secretB, overlapAB, pathSecretB)
	require.Nil(t, err)
	require.True(t, privB.Consistent(*pub))

	// B updates, A processes
	leafB := randomBytes(32)
	privB, path, err = pub.Encap(indexB, context, leafB, sigPrivB, nil)
	require.Nil(t, err)

	err = pub.Merge(indexB, *path)
	require.Nil(t, err)
	require.True(t, privB.Consistent(*pub))

	privA, err = privA.Decap(indexB, pub.Size(), context, *path)
	require.Nil(t, err)
	require.True(t, privA.Consistent(*pub))
}
