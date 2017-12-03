package mls

import (
	"bytes"
	"testing"
)

var (
	aLeafData = [][]byte{
		[]byte("a"),
		[]byte("b"),
		[]byte("c"),
		[]byte("d"),
		[]byte("e"),
	}
)

func TestMerkleTree(t *testing.T) {
	aLeaves := make([][]byte, len(aLeafData))
	aLeafNodes := make([]Node, len(aLeafData))
	for i, data := range aLeafData {
		aLeaves[i] = merkleLeaf(data)
		aLeafNodes[i] = aLeaves[i]
	}

	ab := merklePairHash(aLeaves[0], aLeaves[1])
	cd := merklePairHash(aLeaves[2], aLeaves[3])
	abcd := merklePairHash(ab, cd)
	abcde := merklePairHash(abcd, aLeaves[4])

	tree, err := newTreeFromLeaves(merkleNodeDefn, aLeafNodes)
	if err != nil {
		t.Fatalf("Error building tree: %v", err)
	}

	root, err := tree.Root()
	if err != nil {
		t.Fatalf("Error fetching tree root: %v", err)
	}

	rootData, ok := root.([]byte)
	if !ok {
		t.Fatalf("Merkle tree root not of type []byte")
	}

	if !merkleNodeDefn.valid(root) {
		t.Fatalf("Merkle tree root is not valid")
	}

	if !merkleNodeDefn.valid(root) {
		t.Fatalf("Merkle tree root is not equal to itself")
	}

	if !bytes.Equal(rootData, abcde) {
		t.Fatalf("Incorrect Merkle tree root: %x != %x", rootData, abcde)
	}
}

func TestECDHTree(t *testing.T) {
	aLeaves := make([]*ecdhKey, len(aLeafData))
	aLeafNodes := make([]Node, len(aLeafData))
	for i, data := range aLeafData {
		aLeaves[i] = ecdhKeyFromData(data)
		aLeafNodes[i] = aLeaves[i]
	}

	ab := ecdhKeyFromData(aLeaves[0].derive(aLeaves[1].publicKey))
	cd := ecdhKeyFromData(aLeaves[2].derive(aLeaves[3].publicKey))
	abcd := ecdhKeyFromData(ab.derive(cd.publicKey))
	abcde := ecdhKeyFromData(abcd.derive(aLeaves[4].publicKey))

	tree, err := newTreeFromLeaves(ecdhNodeDefn, aLeafNodes)
	if err != nil {
		t.Fatalf("Error building tree: %v", err)
	}

	root, err := tree.Root()
	if err != nil {
		t.Fatalf("Error fetching tree root: %v", err)
	}

	rootData, ok := root.(*ecdhKey)
	if !ok {
		t.Fatalf("ECDH tree root not of type *ecdhKey")
	}

	if !ecdhNodeDefn.valid(root) {
		t.Fatalf("ECDH tree root is not valid")
	}

	if !ecdhNodeDefn.valid(root) {
		t.Fatalf("ECDH tree root is not equal to itself")
	}

	if rootData.publicKey.x.Cmp(abcde.publicKey.x) != 0 ||
		rootData.publicKey.y.Cmp(abcde.publicKey.y) != 0 {
		t.Fatalf("Incorrect ECDH tree root: %x != %x", rootData, abcde)
	}
}
