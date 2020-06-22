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

	cred := NewBasicCredential(userID, suite.Scheme(), sigPriv.PublicKey)

	kp, err := NewKeyPackageWithInitKey(suite, initPriv.PublicKey, cred, sigPriv)

	return secret, sigPriv, kp
}

func TestTreeKEM(t *testing.T) {
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
	var path *DirectPath
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

		overlap, pathSecret, ok := privs[i].SharedPathSecret(joiner)
		require.True(t, ok)
		require.NotNil(t, pathSecret)

		// New joiner initializes their private key
		privs[i+1] = NewTreeKEMPrivateKeyForJoiner(suite, joiner, pub.Size(), secret, overlap, pathSecret)
		require.True(t, privs[i+1].Consistent(*privs[i]))
		require.True(t, privs[i+1].ConsistentPub(*pub))

		// Other members update their private keys
		for j := 0; j < i; j++ {
			err = privs[j].Decap(adder, *pub, context, *path)
			require.Nil(t, err)
			require.True(t, privs[j].Consistent(*privs[i]))
			require.True(t, privs[j].ConsistentPub(*pub))
		}
	}
}

func generateRatchetTreeVectors(t *testing.T) []byte {
	return nil // TODO(RLB)
}

func verifyRatchetTreeVectors(t *testing.T, data []byte) {
	// TODO(RLB)
}
