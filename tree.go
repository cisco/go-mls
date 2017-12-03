package mls

import (
	"fmt"
)

type Node interface{}

type nodeDefinition struct {
	valid   func(x Node) bool
	equal   func(x, y Node) bool
	create  func(d []byte) Node
	combine func(x, y Node) ([]byte, error)
}

var (
	IncompatibleNodesError = fmt.Errorf("Nodes cannot be combined")
	MissingNodeError       = fmt.Errorf("Missing node")
	InvalidNodeError       = fmt.Errorf("Invalid node type")
	InvalidPathError       = fmt.Errorf("Invalid update path")
	InvalidParameterError  = fmt.Errorf("Invalid parameter")
)

type tree struct {
	defn  *nodeDefinition
	size  uint
	nodes map[uint]Node
}

type FrontierEntry struct {
	Value Node
	Size  uint
}

type Frontier struct {
	defn    *nodeDefinition
	Entries []FrontierEntry
}

type Copath struct {
	defn  *nodeDefinition
	Size  uint
	Index uint
	Nodes []Node
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
	for i, l := range leaves {
		if !defn.valid(l) {
			return nil, InvalidNodeError
		}

		nodes[2*uint(i)] = l
	}

	t := &tree{
		defn:  defn,
		size:  uint(len(leaves)),
		nodes: nodes,
	}

	err := t.Build()
	if err != nil {
		return nil, err
	}

	return t, nil
}

func newTreeFromFrontier(F *Frontier) (*tree, error) {
	if F.defn == nil {
		return nil, InvalidParameterError
	}

	size := uint(0)
	for _, entry := range F.Entries {
		size += entry.Size
	}

	f := frontier(size)
	if len(F.Entries) != len(f) {
		return nil, InvalidPathError
	}

	nodes := map[uint]Node{}
	for i, j := range f {
		nodes[j] = F.Entries[i].Value
	}

	t := &tree{
		defn:  F.defn,
		size:  size,
		nodes: nodes,
	}

	err := t.Build()
	if err != nil {
		return nil, err
	}

	return t, nil
}

func newTreeFromCopath(C *Copath) (*tree, error) {
	if C.defn == nil {
		return nil, InvalidParameterError
	}

	c := copath(2*C.Index, C.Size)
	if len(C.Nodes) != len(c) {
		return nil, InvalidPathError
	}

	nodes := map[uint]Node{}
	for i, j := range c {
		nodes[j] = C.Nodes[i]
	}

	t := &tree{
		defn:  C.defn,
		size:  C.Size,
		nodes: nodes,
	}

	err := t.Build()
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
		if ok && !t.defn.equal(x, y) {
			return false
		}
	}

	return true
}

func (t *tree) Build() error {
	new := t.size
	for new > 0 {
		new = 0
		for i := uint(0); i < nodeWidth(t.size); i += 1 {
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
			if err != nil && err != IncompatibleNodesError {
				return err
			}

			node := t.defn.create(value)
			if !t.defn.equal(t.nodes[i], node) {
				t.nodes[i] = node
				new += 1
			}
		}
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
	return t.Build()
}

// Update a leaf only (and compute intermediates)
func (t *tree) Update(index uint, leaf Node) error {
	t.nodes[2*index] = leaf
	return t.Build()
}

// Update with a direct path from a leaf
func (t *tree) UpdateWithPath(index uint, path []Node) error {
	d := dirpath(2*index, t.size)
	d = append([]uint{2 * index}, d...)
	if len(path) != len(d) {
		// return InvalidPathError
		fmt.Println(dirpath(index, t.size))
		fmt.Println(d)
		return fmt.Errorf("Invalid update path: %v != %v", len(path), len(d))
	}

	for i, j := range d {
		t.nodes[j] = path[i]
	}
	return t.Build()
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

func (t tree) Copath(index uint) (*Copath, error) {
	c := copath(2*index, t.size)
	C := make([]Node, len(c))
	var ok bool
	for i, j := range c {
		C[i], ok = t.nodes[j]
		if !ok {
			return nil, MissingNodeError
		}
	}

	return &Copath{
		defn:  t.defn,
		Size:  t.size,
		Index: index,
		Nodes: C,
	}, nil
}

func (t tree) Frontier() (*Frontier, error) {
	f := frontier(t.size)
	F := make([]FrontierEntry, len(f))
	for i, j := range f {
		node, ok := t.nodes[j]
		if !ok {
			return nil, MissingNodeError
		}

		F[i] = FrontierEntry{
			Value: node,
			Size:  subtreeSize(j, t.size),
		}
	}

	return &Frontier{defn: t.defn, Entries: F}, nil
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
