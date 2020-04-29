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
		err := tree.AddLeaf(LeafIndex(i), *keyPackages[i])
		require.Nil(t, err)
	}

	// Encap to fill in the tree
	for i := range keyPackages {
		_, _, _, err := tree.Encap(LeafIndex(i), []byte{}, []byte{byte(i)})
		require.Nil(t, err)
	}

	return tree
}

func TestRatchetTreeEncapDecap(t *testing.T) {
	// Create keyPackages
	groupSize := 5
	scheme := suite.scheme()
	sigPrivs := make([]SignaturePrivateKey, groupSize)
	initPrivs := make([]HPKEPrivateKey, groupSize)
	keyPackages := make([]*KeyPackage, groupSize)

	var err error
	for i := range keyPackages {
		sigPrivs[i], err = scheme.Generate()
		require.Nil(t, err)

		cred := NewBasicCredential(userID, scheme, &sigPrivs[i])

		keyPackages[i], err = NewKeyPackage(suite, cred)
		require.Nil(t, err)

		initPrivs[i] = *keyPackages[i].privateKey
	}

	// Build trees from the keyPackages
	trees := make([]*RatchetTree, groupSize)
	for i := range trees {
		trees[i] = NewRatchetTree(suite)
		err := trees[i].AddLeaf(LeafIndex(i), *keyPackages[i])
		require.Nil(t, err)

		keyPackages[i].privateKey = nil
	}

	for i := range trees {
		for j := range trees {
			if i == j {
				continue
			}

			err := trees[i].AddLeaf(LeafIndex(j), *keyPackages[j])
			require.Nil(t, err)
		}
	}

	// Verify that tree is parent-hash-valid with only leaves populated (which
	// should be vacuously true because no parent nodes have values)
	for i := range trees {
		require.True(t, trees[i].ParentHashValid())
	}

	// Encap and re-sign from each one, decap at all the others
	for i := range trees {
		from := LeafIndex(i)
		context := []byte{}
		leafSecret := []byte{byte(i)}
		path, leafParentHash, secretE, err := trees[i].Encap(from, context, leafSecret)
		require.Nil(t, err)

		kp, found := trees[i].KeyPackage(from)
		require.True(t, found)

		phe := ParentHashExtension{leafParentHash}
		err = kp.SetExtensions([]ExtensionBody{phe})
		require.Nil(t, err)
		err = kp.Sign()
		require.Nil(t, err)

		err = trees[i].SetLeaf(from, kp)
		require.Nil(t, err)

		require.True(t, trees[i].ParentHashValid())

		for j := range trees {
			if i == j {
				continue
			}

			secretD, err := trees[j].Decap(from, context, path)
			require.Nil(t, err)
			require.Equal(t, secretE, secretD)

			err = trees[j].SetLeaf(from, kp)
			require.Nil(t, err)

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
