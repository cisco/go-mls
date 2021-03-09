package vectors

import (
	"fmt"
	"reflect"

	"github.com/cisco/go-mls/v0/mls/tree-math"
)

func checkDeepEqual(label string, actual, expected interface{}) error {
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf("%s : %v != %v", label, actual, expected)
	}
	return nil
}

type TreeMath struct {
	NLeaves treeMath.LeafCount    `json:"n_leaves"`
	NNodes  treeMath.NodeCount    `json:"n_nodes"`
	Root    []treeMath.NodeIndex  `json:"root"`
	Left    []*treeMath.NodeIndex `json:"left"`
	Right   []*treeMath.NodeIndex `json:"right"`
	Parent  []*treeMath.NodeIndex `json:"parent"`
	Sibling []*treeMath.NodeIndex `json:"sibling"`
}

func NewTreeMath(nLeavesIn uint32) (TreeMath, error) {
	nLeaves := treeMath.LeafCount(nLeavesIn)
	nNodes := treeMath.NodeWidth(nLeaves)

	vec := TreeMath{
		NLeaves: nLeaves,
		NNodes:  nNodes,
		Root:    make([]treeMath.NodeIndex, nLeaves),
		Left:    make([]*treeMath.NodeIndex, nNodes),
		Right:   make([]*treeMath.NodeIndex, nNodes),
		Parent:  make([]*treeMath.NodeIndex, nNodes),
		Sibling: make([]*treeMath.NodeIndex, nNodes),
	}

	for i := range vec.Root {
		vec.Root[i] = treeMath.Root(treeMath.LeafCount(i + 1))
	}

	for i := range vec.Left {
		vec.Left[i] = treeMath.Left(treeMath.NodeIndex(i))
		vec.Right[i] = treeMath.Right(treeMath.NodeIndex(i), nLeaves)
		vec.Parent[i] = treeMath.Parent(treeMath.NodeIndex(i), nLeaves)
		vec.Sibling[i] = treeMath.Sibling(treeMath.NodeIndex(i), nLeaves)
	}

	return vec, nil
}

func (vec TreeMath) Verify() error {
	err := checkDeepEqual("Node count", vec.NNodes, treeMath.NodeWidth(vec.NLeaves))
	if err != nil {
		return err
	}

	for i, r := range vec.Root {
		label := fmt.Sprintf("Root[%d]", i)
		err := checkDeepEqual(label, r, treeMath.Root(treeMath.LeafCount(i+1)))
		if err != nil {
			return err
		}
	}

	for i := treeMath.NodeIndex(0); i < treeMath.NodeIndex(vec.NNodes); i++ {
		label := fmt.Sprintf("Left[%d]", i)
		err := checkDeepEqual(label, vec.Left[i], treeMath.Left(i))
		if err != nil {
			return err
		}

		label = fmt.Sprintf("Right[%d]", i)
		err = checkDeepEqual(label, vec.Right[i], treeMath.Right(i, vec.NLeaves))
		if err != nil {
			return err
		}

		label = fmt.Sprintf("Parent[%d]", i)
		err = checkDeepEqual(label, vec.Parent[i], treeMath.Parent(i, vec.NLeaves))
		if err != nil {
			return err
		}

		label = fmt.Sprintf("Sibling[%d]", i)
		err = checkDeepEqual(label, vec.Sibling[i], treeMath.Sibling(i, vec.NLeaves))
		if err != nil {
			return err
		}
		// TODO continue
	}

	return nil
}
