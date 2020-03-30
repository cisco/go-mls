package mls

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func newTestRatchetTree(t *testing.T, suite CipherSuite, secrets [][]byte) *RatchetTree {
	scheme := suite.scheme()

	keyPackages := make([]*KeyPackage, len(secrets))
	for i := range keyPackages {
		initPriv, err := suite.hpke().Derive(secrets[i])
		require.Nil(t, err)

		sigPriv, err := scheme.Derive(secrets[i])
		require.Nil(t, err)

		cred := NewBasicCredential(userID, scheme, &sigPriv)

		keyPackages[i], err = NewKeyPackageWithInitKey(suite, initPriv, cred)
		require.Nil(t, err)

		keyPackages[i].privateKey = nil
	}

	// Build trees from the keyPackages
	tree := NewRatchetTree(suite)
	for i := range keyPackages {
		err := tree.AddLeaf(leafIndex(i), *keyPackages[i])
		require.Nil(t, err)
	}

	// Encap to fill in the tree
	for i := range keyPackages {
		_, _, _, err := tree.Encap(leafIndex(i), []byte{}, []byte{byte(i)})
		require.Nil(t, err)
	}

	return tree
}

func TestRatchetTreeEncapDecap(t *testing.T) {
	// Create keyPackages
	groupSize := 5
	scheme := suite.scheme()
	keyPackages := make([]*KeyPackage, groupSize)
	for i := range keyPackages {
		sigPriv, err := scheme.Generate()
		require.Nil(t, err)

		cred := NewBasicCredential(userID, scheme, &sigPriv)

		keyPackages[i], err = NewKeyPackage(suite, cred)
		require.Nil(t, err)
	}

	// Build trees from the keyPackages
	trees := make([]*RatchetTree, groupSize)
	for i := range trees {
		trees[i] = NewRatchetTree(suite)
		err := trees[i].AddLeaf(leafIndex(i), *keyPackages[i])
		require.Nil(t, err)

		keyPackages[i].privateKey = nil
	}

	for i := range trees {
		for j := range trees {
			if i == j {
				continue
			}

			err := trees[i].AddLeaf(leafIndex(j), *keyPackages[j])
			require.Nil(t, err)
		}
	}

	// Verify that tree is parent-hash-valid with only leaves populated (which
	// should be vacuously true because no parent nodes have values)
	for i := range trees {
		require.True(t, trees[i].ParentHashValid())
	}

	// Encap from each one, decap at all the others
	for i := range trees {
		from := leafIndex(i)
		context := []byte{}
		leafSecret := []byte{byte(i)}
		path, _, secretE, err := trees[i].Encap(from, context, leafSecret)
		require.Nil(t, err)

		require.True(t, trees[i].ParentHashValid())

		for j := range trees {
			t.Logf("%d -> %d", i, j)
			if i == j {
				continue
			}

			secretD, err := trees[j].Decap(from, context, path)
			require.Nil(t, err)
			require.Equal(t, secretE, secretD)

			require.True(t, trees[j].ParentHashValid())
		}
	}
}

func generateRatchetTreeVectors(t *testing.T) []byte {
	return nil // TODO(RLB)
}

func verifyRatchetTreeVectors(t *testing.T, data []byte) {
	// TODO(RLB)
}
