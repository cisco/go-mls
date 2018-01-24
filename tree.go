package mls

import (
	"fmt"
)

type Node interface{}

type nodeDefinition struct {
	valid       func(x Node) bool
	equal       func(x, y Node) bool
	publicEqual func(x, y Node) bool
	create      func(d []byte) Node
	combine     func(x, y Node) ([]byte, error)
}

var (
	IncompatibleNodesError = fmt.Errorf("Nodes cannot be combined")
	MissingNodeError       = fmt.Errorf("Missing node")
	InvalidIndexError      = fmt.Errorf("Invalid index")
	InvalidNodeError       = fmt.Errorf("Invalid node type")
	InvalidPathError       = fmt.Errorf("Invalid update path")
	InvalidParameterError  = fmt.Errorf("Invalid parameter")
)

type tree struct {
	defn  *nodeDefinition
	size  uint
	nodes map[uint]Node
}

func newTree(defn *nodeDefinition) *tree {
	return &tree{
		defn:  defn,
		size:  0,
		nodes: map[uint]Node{},
	}
}

func newTreeFromLeaves(defn *nodeDefinition, leaves []Node) (*tree, error) {
	nodes := map[uint]Node{}
	new := make([]uint, len(leaves))
	for i, l := range leaves {
		if !defn.valid(l) {
			return nil, InvalidNodeError
		}

		nodes[2*uint(i)] = l
		new[i] = 2 * uint(i)
	}

	t := &tree{
		defn:  defn,
		size:  uint(len(leaves)),
		nodes: nodes,
	}

	err := t.Build(new)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func newTreeFromFrontier(defn *nodeDefinition, size uint, F []Node) (*tree, error) {
	if defn == nil {
		return nil, InvalidParameterError
	}

	f := frontier(size)
	if len(F) != len(f) {
		return nil, InvalidPathError
	}

	nodes := map[uint]Node{}
	for i, j := range f {
		nodes[j] = F[i]
	}

	t := &tree{
		defn:  defn,
		size:  size,
		nodes: nodes,
	}

	err := t.Build(f)
	if err != nil {
		return nil, err
	}

	return t, nil
}

func newTreeFromCopath(defn *nodeDefinition, index, size uint, C []Node) (*tree, error) {
	if defn == nil {
		return nil, InvalidParameterError
	}

	if index >= size {
		return nil, InvalidParameterError
	}

	c := copath(2*index, size)
	if len(C) != len(c) {
		return nil, InvalidPathError
	}

	nodes := map[uint]Node{}
	for i, j := range c {
		nodes[j] = C[i]
	}

	t := &tree{
		defn:  defn,
		size:  size,
		nodes: nodes,
	}

	err := t.Build(c)
	if err != nil {
		return nil, err
	}

	return t, nil
}

// Two trees are equal if they have the same node definition and size,
// and the nodes they have in common are identical.
func (t *tree) Equal(other *tree) bool {
	if t.defn != other.defn {
		return false
	}

	if t.size != other.size {
		return false
	}

	for i, x := range t.nodes {
		y, ok := other.nodes[i]
		if ok && !t.defn.publicEqual(x, y) {
			return false
		}
	}

	return true
}

func (t *tree) Build(new []uint) error {
	toUpdate := map[uint]bool{}
	for _, n := range new {
		p := parent(n, t.size)
		if p != n {
			toUpdate[p] = true
		}
	}

	for len(toUpdate) > 0 {
		nextToUpdate := map[uint]bool{}

		for i := range toUpdate {
			l := left(i)
			r := right(i, t.size)

			if l == i || r == i {
				continue
			}

			ln, okl := t.nodes[l]
			rn, okr := t.nodes[r]
			if !okl || !okr {
				continue
			}

			value, err := t.defn.combine(ln, rn)
			if err == IncompatibleNodesError {
				continue
			}
			if err != nil {
				return err
			}

			node := t.defn.create(value)
			if !t.defn.equal(t.nodes[i], node) {
				t.nodes[i] = node

				p := parent(i, t.size)
				if p != i {
					nextToUpdate[p] = true
				}
			}
		}

		toUpdate = nextToUpdate
	}

	return nil
}

// Mutators

// Add a leaf to the tree
func (t *tree) Add(leaf Node) error {
	if !t.defn.valid(leaf) {
		return InvalidNodeError
	}

	t.nodes[2*t.size] = leaf
	t.size += 1
	return t.Build([]uint{2 * (t.size - 1)})
}

func (t *tree) AddWithPath(path []Node) error {
	t.size += 1
	return t.UpdateWithPath(t.size-1, path)
}

// Update a leaf only (and compute intermediates)
func (t *tree) Update(index uint, leaf Node) error {
	if index >= t.size {
		return InvalidIndexError
	}

	t.nodes[2*index] = leaf
	return t.Build([]uint{2 * index})
}

// Update with a direct path from a leaf
func (t *tree) UpdateWithPath(index uint, path []Node) error {
	if index >= t.size {
		return InvalidIndexError
	}

	d := dirpath(2*index, t.size)
	d = append(d, 2*index)
	if len(path) != len(d) {
		return InvalidPathError
	}

	for i, j := range d {
		if !t.defn.valid(path[i]) {
			return InvalidNodeError
		}

		t.nodes[j] = path[i]
	}
	return t.Build(d)
}

// Extractors
func (t tree) HasAllLeaves() bool {
	for i := uint(0); i < t.size; i += 1 {
		if _, ok := t.nodes[2*i]; !ok {
			return false
		}
	}
	return true
}

func (t tree) Leaves() ([]Node, error) {
	if !t.HasAllLeaves() {
		return nil, MissingNodeError
	}

	ll := make([]Node, t.size)
	for i := uint(0); i < t.size; i += 1 {
		ll[i] = t.nodes[2*i]
	}
	return ll, nil
}

func (t tree) Root() (Node, error) {
	root, ok := t.nodes[root(t.size)]
	if !ok {
		return nil, MissingNodeError
	}

	return root, nil
}

func (t tree) DirectPath(index uint) ([]Node, error) {
	if index >= t.size {
		return nil, InvalidIndexError
	}

	d := dirpath(2*index, t.size)
	d = append(d, 2*index)
	D := make([]Node, len(d))
	var ok bool
	for i, j := range d {
		D[i], ok = t.nodes[j]
		if !ok {
			return nil, MissingNodeError
		}
	}

	return D, nil
}

func (t tree) Copath(index uint) ([]Node, error) {
	if index >= t.size {
		return nil, InvalidIndexError
	}

	c := copath(2*index, t.size)
	C := make([]Node, len(c))
	var ok bool
	for i, j := range c {
		C[i], ok = t.nodes[j]
		if !ok {
			return nil, MissingNodeError
		}
	}

	return C, nil
}

func (t tree) Frontier() ([]Node, error) {
	f := frontier(t.size)
	F := make([]Node, len(f))
	for i, j := range f {
		node, ok := t.nodes[j]
		if !ok {
			return nil, MissingNodeError
		}

		F[i] = node
	}

	return F, nil
}

func (t tree) UpdatePath(index uint, newValue Node) ([]Node, error) {
	c := copath(2*index, t.size)
	nodes := make([]Node, len(c))

	nodes[len(nodes)-1] = newValue
	for i := len(nodes) - 1; i > 0; i -= 1 {
		copathNode, ok := t.nodes[c[i]]
		if !ok {
			return nil, MissingNodeError
		}

		// Determine whether the copath node is the left or right sibling
		// of nodes[i]
		var data []byte
		var err error
		s := sibling(c[i], t.size)
		if s < c[i] {
			data, err = t.defn.combine(nodes[i], copathNode)
		} else {
			data, err = t.defn.combine(copathNode, nodes[i])
		}

		if err != nil {
			return nil, err
		}

		nodes[i-1] = t.defn.create(data)
	}

	return nodes, nil
}

// Note that missing nodes here do not result in MissingNodeError.
// Instead, they are passed on to the caller as nil.
func (t tree) Puncture(punctures []uint) []Node {
	heads := puncture(t.size, punctures)
	nodes := make([]Node, len(heads))
	for i, h := range heads {
		nodes[i] = t.nodes[h]
	}

	return nodes
}
