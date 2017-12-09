package mls

import (
	"bytes"
	"reflect"
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
	aLeaves := make([]MerkleNode, len(aLeafData))
	aLeafNodes := make([]Node, len(aLeafData))
	for i, data := range aLeafData {
		aLeaves[i] = MerkleNode{merkleLeaf(data)}
		aLeafNodes[i] = aLeaves[i]
	}

	ab, _ := merkleNodeDefn.combine(aLeaves[0], aLeaves[1])
	cd, _ := merkleNodeDefn.combine(aLeaves[2], aLeaves[3])
	abcd, _ := merkleNodeDefn.combine(merkleNodeDefn.create(ab), merkleNodeDefn.create(cd))
	abcde, _ := merkleNodeDefn.combine(merkleNodeDefn.create(abcd), aLeaves[4])

	tree, err := newTreeFromLeaves(merkleNodeDefn, aLeafNodes)
	if err != nil {
		t.Fatalf("Error building tree: %v", err)
	}

	root, err := tree.Root()
	if err != nil {
		t.Fatalf("Error fetching tree root: %v", err)
	}

	rootData, ok := root.(MerkleNode)
	if !ok {
		t.Fatalf("Merkle tree root not of type MerkleNode")
	}

	if !merkleNodeDefn.valid(root) {
		t.Fatalf("Merkle tree root is not valid")
	}

	if !merkleNodeDefn.valid(root) {
		t.Fatalf("Merkle tree root is not equal to itself")
	}

	if !bytes.Equal(rootData.Value, abcde) {
		t.Fatalf("Incorrect Merkle tree root: %x != %x", rootData, abcde)
	}
}

func TestDHDHTree(t *testing.T) {
	aLeaves := make([]*DHNode, len(aLeafData))
	aLeafNodes := make([]Node, len(aLeafData))
	for i, data := range aLeafData {
		aLeaves[i] = DHNodeFromData(data)
		aLeafNodes[i] = aLeaves[i]
	}

	ab := DHNodeFromData(aLeaves[0].PrivateKey.derive(aLeaves[1].PrivateKey.PublicKey))
	cd := DHNodeFromData(aLeaves[2].PrivateKey.derive(aLeaves[3].PrivateKey.PublicKey))
	abcd := DHNodeFromData(ab.PrivateKey.derive(cd.PrivateKey.PublicKey))
	abcde := DHNodeFromData(abcd.PrivateKey.derive(aLeaves[4].PrivateKey.PublicKey))

	tree, err := newTreeFromLeaves(dhNodeDefn, aLeafNodes)
	if err != nil {
		t.Fatalf("Error building tree: %v", err)
	}

	root, err := tree.Root()
	if err != nil {
		t.Fatalf("Error fetching tree root: %v", err)
	}

	rootData, ok := root.(*DHNode)
	if !ok {
		t.Fatalf("DHDH tree root not of type *ecdhKey")
	}

	if !dhNodeDefn.valid(root) {
		t.Fatalf("DHDH tree root is not valid")
	}

	if !dhNodeDefn.valid(root) {
		t.Fatalf("DHDH tree root is not equal to itself")
	}

	if !reflect.DeepEqual(rootData.PrivateKey.PublicKey, abcde.PrivateKey.PublicKey) {
		t.Fatalf("Incorrect DHDH tree root: %x != %x", rootData, abcde)
	}
}
