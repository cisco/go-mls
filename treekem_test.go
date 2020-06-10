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

func TestTreeKEMMulti(t *testing.T) {
	groupSize := 10
	var err error

	pub := NewTreeKEMPublicKey(suite)
	privs := make([]*TreeKEMPrivateKey, groupSize)
	sigPrivs := make([]SignaturePrivateKey, groupSize)

	// Make a new one-person pub + priv
	secret, sigPriv, kp := newKeyPackage(t)
	sigPrivs[0] = sigPriv

	index := pub.AddLeaf(*kp)
	require.Equal(t, index, LeafIndex(0))

	privs[0] = NewTreeKEMPrivateKey(suite, pub.Size(), index, secret)
	require.True(t, privs[0].ConsistentPub(*pub))

	// Each member adds the next
	var path *TreeKEMPath
	for i := 0; i < groupSize-1; i++ {
		adder := LeafIndex(i)
		joiner := LeafIndex(i + 1)
		context := []byte{byte(i)}
		secret, sigPriv, kp := newKeyPackage(t)
		sigPrivs[i+1] = sigPriv

		index := pub.AddLeaf(*kp)
		require.Equal(t, index, joiner)

		// Add the new joiner
		leafSecret := randomBytes(32)
		privs[i], path, err = pub.Encap(adder, context, leafSecret, sigPrivs[i], nil)
		require.Nil(t, err)
		require.Nil(t, path.ParentHashValid(suite))

		err = pub.Merge(adder, *path)
		require.Nil(t, err)
		require.True(t, privs[i].ConsistentPub(*pub))

		overlap, pathSecret, err := privs[i].SharedPathSecret(joiner)
		require.Nil(t, err)

		// New joiner initializes their private key
		privs[i+1] = NewTreeKEMPrivateKeyForJoiner(suite, joiner, pub.Size(), secret, overlap, pathSecret)
		require.True(t, privs[i+1].Consistent(*privs[i]))
		require.True(t, privs[i+1].ConsistentPub(*pub))

		// Other members update their private keys
		for j := 0; j < i; j++ {
			err = privs[j].Decap(adder, pub.Size(), context, *path)
			require.Nil(t, err)
			require.True(t, privs[j].Consistent(*privs[i]))
			require.True(t, privs[j].ConsistentPub(*pub))
		}
	}
}

func TestTreeKEM(t *testing.T) {
	context := randomBytes(32)

	// Make a new one-person pub + priv
	pub := NewTreeKEMPublicKey(suite)

	// AddLeaf + Encap + Merge
	secretA, sigPrivA, kpA := newKeyPackage(t)

	indexA := pub.AddLeaf(*kpA)
	require.Equal(t, indexA, LeafIndex(0))

	privA := NewTreeKEMPrivateKey(suite, pub.Size(), indexA, secretA)
	require.True(t, privA.ConsistentPub(*pub))

	leafA := randomBytes(32)
	privA, path, err := pub.Encap(indexA, context, leafA, sigPrivA, nil)
	require.Nil(t, err)
	require.Nil(t, path.ParentHashValid(suite))

	err = pub.Merge(indexA, *path)
	require.Nil(t, err)
	require.True(t, privA.ConsistentPub(*pub))

	// AddLeaf + Encap + Decap + Merge
	secretB, sigPrivB, kpB := newKeyPackage(t)

	indexB := pub.AddLeaf(*kpB)
	require.Equal(t, indexB, LeafIndex(1))

	// Add B
	leafA = randomBytes(32)
	privA, path, err = pub.Encap(indexA, context, leafA, sigPrivA, nil)
	require.Nil(t, err)
	require.Nil(t, path.ParentHashValid(suite))

	err = pub.Merge(indexA, *path)
	require.Nil(t, err)
	require.True(t, privA.ConsistentPub(*pub))

	overlapAB, pathSecretB, err := privA.SharedPathSecret(indexB)
	require.Nil(t, err)

	privB := NewTreeKEMPrivateKeyForJoiner(suite, indexB, pub.Size(), secretB, overlapAB, pathSecretB)
	require.True(t, privB.Consistent(*privA))
	require.True(t, privB.ConsistentPub(*pub))

	// B updates, A processes
	leafB := randomBytes(32)
	privB, path, err = pub.Encap(indexB, context, leafB, sigPrivB, nil)
	require.Nil(t, err)
	require.Nil(t, path.ParentHashValid(suite))

	err = pub.Merge(indexB, *path)
	require.Nil(t, err)
	require.True(t, privB.ConsistentPub(*pub))

	err = privA.Decap(indexB, pub.Size(), context, *path)
	require.Nil(t, err)
	require.True(t, privA.Consistent(*privB))
	require.True(t, privA.ConsistentPub(*pub))
}
