package mls

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// XXX DELE
func prettyPrintTree(t *tree) {
	w := 2
	pad := strings.Repeat(" ", 2*w)
	xxx := strings.Repeat("_", 2*w)

	maxLevel := log2(t.size-1) + 1
	for L := maxLevel; ; L -= 1 {
		for i := uint(0); i < 2*(t.size-1)+1; i += 1 {
			n, ok := t.nodes[i]

			var data []byte
			switch val := n.(type) {
			case []byte:
				data = val
			case (*ECNode):
				data = merkleLeaf(val.PrivateKey.PublicKey.bytes())
			}

			if level(i) != L {
				fmt.Printf("%s ", pad)
			} else if !ok {
				fmt.Printf("%s ", xxx)
			} else {
				fmt.Printf("%x ", data[:w])
			}
		}
		fmt.Printf("\n")

		if L == 0 {
			break
		}
	}
}

var stringNodeDefn = &nodeDefinition{
	valid: func(x Node) bool {
		_, ok := x.(string)
		return ok
	},

	equal: func(x, y Node) bool {
		xs, okx := x.(string)
		ys, oky := y.(string)
		return okx && oky && (xs == ys)
	},

	publicEqual: func(x, y Node) bool {
		xs, okx := x.(string)
		ys, oky := y.(string)
		return okx && oky && (xs == ys)
	},

	create: func(d []byte) Node {
		return string(d)
	},

	combine: func(x, y Node) ([]byte, error) {
		xs, okx := x.(string)
		ys, oky := y.(string)
		if !okx || !oky {
			return nil, InvalidNodeError
		}

		return []byte(xs + ys), nil
	},
}

func TestNewTree(t *testing.T) {
	aDefn := stringNodeDefn
	aSize := uint(3)
	aNodes := map[uint]Node{
		0: "a",
		1: "ab",
		2: "b",
		3: "abc",
		4: "c",
	}

	leaves := []Node{"a", "b", "c"}
	tree, err := newTreeFromLeaves(stringNodeDefn, leaves)

	if err != nil {
		t.Fatalf("Error constructing tree: %v", err)
	}

	if tree.defn != aDefn {
		t.Fatalf("Incorrect tree node definition: %v != %v", tree.defn, aDefn)
	}

	if tree.size != aSize {
		t.Fatalf("Incorrect computed tree size: %v != %v", tree.size, aSize)
	}

	if !reflect.DeepEqual(tree.nodes, aNodes) {
		t.Fatalf("Incorrect computed tree nodes: %v != %v", tree.nodes, aNodes)
	}

	// Test equality
	if !tree.Equal(tree) {
		t.Fatalf("Tree does not equal itself")
	}
}

func TestNewTreeFromCopath(t *testing.T) {
	aIndex := uint(0)
	aSize := uint(3)
	aC := []Node{"b", "c"}

	// Test newTree / Copath() round trip
	tree, err := newTreeFromCopath(stringNodeDefn, aIndex, aSize, aC)
	if err != nil {
		t.Fatalf("Error constructing tree from copath: %v", err)
	}

	C, err := tree.Copath(aIndex)
	if err != nil {
		t.Fatalf("Error fetching copath: %v", err)
	}

	if !reflect.DeepEqual(C, aC) {
		t.Fatalf("Incorrect copath value: %v != %v", C, aC)
	}
}

func TestNewTreeFromFrontier(t *testing.T) {
	aDefn := stringNodeDefn
	aSize := uint(3)
	aF := []Node{"ab", "c"}

	// Test newTree / Frontier() round trip
	tree, err := newTreeFromFrontier(aDefn, aSize, aF)
	if err != nil {
		t.Fatalf("Error constructing tree from frontier: %v", err)
	}

	F, err := tree.Frontier()
	if err != nil {
		t.Fatalf("Error fetching frontier: %v", err)
	}

	if !reflect.DeepEqual(F, aF) {
		t.Fatalf("Incorrect frontier value: %v != %v", F, aF)
	}
}

func TestTreeAdd(t *testing.T) {
	aDefn := stringNodeDefn
	aSize := uint(5)
	aLeaves := []Node{"a", "b", "c", "d", "e"}
	aNodes := map[uint]Node{
		0: "a",
		1: "ab",
		2: "b",
		3: "abcd",
		4: "c",
		5: "cd",
		6: "d",
		7: "abcde",
		8: "e",
	}
	aFrontier := []Node{"abcd", "e"}

	// Build tree by additions
	tree := newTree(stringNodeDefn)
	for _, leaf := range aLeaves {
		if err := tree.Add(leaf); err != nil {
			t.Fatalf("Error adding leaf: %v", err)
		}
	}

	// Verify contents directly
	if tree.size != aSize {
		t.Fatalf("Incorrect computed tree size: %v != %v", tree.size, aSize)
	}

	if !reflect.DeepEqual(tree.nodes, aNodes) {
		t.Fatalf("Incorrect computed tree nodes: %v != %v", tree.nodes, aNodes)
	}

	// Verify that it's the same as a tree built directly
	aTree, _ := newTreeFromLeaves(aDefn, aLeaves)
	if !aTree.Equal(tree) {
		t.Fatalf("Add-built tree does not equal leaf-built tree: %v != %v", aTree, tree)
	}

	// Verify that it has all its leaves
	if !tree.HasAllLeaves() {
		t.Fatalf("Add-built tree does not have all leaves: %v", tree)
	}

	// Verify that its leaves are as expected
	leaves, err := tree.Leaves()
	if err != nil {
		t.Fatalf("Error fetching leaves: %v", err)
	}

	if !reflect.DeepEqual(leaves, aLeaves) {
		t.Fatalf("Add-built tree does not expected leaves: %v != %v", leaves, aLeaves)
	}

	// Verify that the Frontier is as expected
	frontier, err := tree.Frontier()
	if err != nil {
		t.Fatalf("Error fetching frontier: %v", err)
	}

	if !reflect.DeepEqual(frontier, aFrontier) {
		t.Fatalf("Add-built tree does not expected frontier: %v != %v", frontier, aFrontier)
	}

	// Verify that Copaths have plausible values
	for i := uint(0); i < tree.size; i += 1 {
		c := copath(2*i, tree.size)

		C, err := tree.Copath(i)
		if err != nil {
			t.Fatalf("Error fetching copath @ %v: %v", i, err)
		}

		if len(C) != len(c) {
			t.Fatalf("Copath has wrong path length @ %v: %v != %v", i, len(C), len(c))
		}
	}
}

func TestTreeUpdate(t *testing.T) {
	aSize := uint(5)
	aLeaves := []Node{"a", "b", "c", "d", "e"}

	aIndex1 := uint(3)
	aNewLeaf1 := "x"
	aNodes1 := map[uint]Node{
		0: "a",
		1: "ab",
		2: "b",
		3: "abcx",
		4: "c",
		5: "cx",
		6: "x",
		7: "abcxe",
		8: "e",
	}

	aIndex2 := uint(1)
	aUpdatePath2 := []Node{"aycx", "ay", "y"}
	aNodes2 := map[uint]Node{
		0: "a",
		1: "ay",
		2: "y",
		3: "aycx",
		4: "c",
		5: "cx",
		6: "x",
		7: "aycxe",
		8: "e",
	}

	// Build tree, then update leaf
	tree, _ := newTreeFromLeaves(stringNodeDefn, aLeaves)
	if err := tree.Update(aIndex1, aNewLeaf1); err != nil {
		t.Fatalf("Error updating leaf: %v", err)
	}

	if tree.size != aSize {
		t.Fatalf("Incorrect computed tree size: %v != %v", tree.size, aSize)
	}

	if !reflect.DeepEqual(tree.nodes, aNodes1) {
		t.Fatalf("Incorrect computed tree nodes: %v != %v", tree.nodes, aNodes1)
	}

	// Update another leaf with a full path
	if err := tree.UpdateWithPath(aIndex2, aUpdatePath2); err != nil {
		t.Fatalf("Error updating leaf: %v", err)
	}

	if tree.size != aSize {
		t.Fatalf("Incorrect computed tree size: %v != %v", tree.size, aSize)
	}

	if !reflect.DeepEqual(tree.nodes, aNodes2) {
		t.Fatalf("Incorrect computed tree nodes: %v != %v", tree.nodes, aNodes2)
	}
}

func TestTreeUpdatePath(t *testing.T) {
	aLeaves := []Node{"a", "b", "c", "d", "e"}
	aIndex := uint(3)
	aNewLeaf := "x"
	aPath := []Node{"abcx", "cx", "x"}

	// Build tree, then generate update path
	tree, _ := newTreeFromLeaves(stringNodeDefn, aLeaves)

	path, err := tree.UpdatePath(aIndex, aNewLeaf)
	if err != nil {
		t.Fatalf("Error creating update path: %v", err)
	}

	if !reflect.DeepEqual(path, aPath) {
		t.Fatalf("Incorrect computed update path: %v != %v", path, aPath)
	}
}
