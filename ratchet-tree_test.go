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
		_, _, err := tree.Encap(leafIndex(i), []byte{}, []byte{byte(i)})
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

	// Encap from each one, decap at all the others
	for i := range trees {
		from := leafIndex(i)
		context := []byte{}
		leafSecret := []byte{byte(i)}
		path, secretE, err := trees[i].Encap(from, context, leafSecret)
		require.Nil(t, err)

		for j := range trees {
			if i == j {
				continue
			}

			secretD, err := trees[j].Decap(from, context, path)
			require.Nil(t, err)
			require.Equal(t, secretE, secretD)
		}
	}
}

func generateRatchetTreeVectors(t *testing.T) []byte {
	return nil // TODO(RLB)
}

func verifyRatchetTreeVectors(t *testing.T, data []byte) {
	// TODO(RLB)
}
