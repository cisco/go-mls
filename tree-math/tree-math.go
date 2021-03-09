package treeMath

// The below functions provide the index calculus for the tree structures used in MLS.
// They are premised on a "flat" representation of a balanced binary tree.  Leaf nodes
// are even-numbered nodes, with the n-th leaf at 2*n.  Intermediate nodes are held in
// odd-numbered nodes.  For example, a 11-element tree has the following structure:
//
//                                              X
//                      X
//          X                       X                       X
//    X           X           X           X           X
// X     X     X     X     X     X     X     X     X     X     X
// 0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f 10 11 12 13 14
//
// This allows us to compute relationships between tree nodes simply by manipulating
// indices, rather than having to maintain complicated structures in memory, even for
// partial trees.  (The storage for a tree can just be a map[int]Node dictionary or
// an array.)  The basic rule is that the high-order bits of parent and child nodes
// have the following relation:
//
//    01x = <00x, 10x>

type LeafIndex uint32
type LeafCount uint32
type NodeIndex uint32
type NodeCount uint32

func toNodeIndex(leaf LeafIndex) NodeIndex {
	return NodeIndex(2 * leaf)
}

func toLeafIndex(node NodeIndex) LeafIndex {
	if node&0x01 != 0 {
		panic("toLeafIndex on non-leaf index")
	}

	return LeafIndex(node) >> 1
}

// Position of the most significant 1 bit
func log2(x NodeCount) uint {
	if x == 0 {
		return 0
	}

	k := uint(0)
	for (x >> k) > 0 {
		k += 1
	}
	return k - 1
}

// Position of the least significant 0 bit
func level(x NodeIndex) uint {
	if x&0x01 == 0 {
		return 0
	}

	k := uint(0)
	for (x>>k)&0x01 == 1 {
		k += 1
	}
	return k
}

// Number of nodes for a tree of size N
func NodeWidth(n LeafCount) NodeCount {
	return NodeCount(2*n - 1)
}

// Number of leaves for a tree with N nodes
func LeafWidth(n NodeCount) LeafCount {
	return LeafCount((n + 1) >> 1)
}

// Index of the root of the tree with N leaves
func Root(n LeafCount) NodeIndex {
	w := NodeWidth(n)
	return NodeIndex((1 << log2(w)) - 1)
}

// Left child of x
func Left(x NodeIndex) *NodeIndex {
	if level(x) == 0 {
		return nil
	}

	out := x ^ (0x01 << (level(x) - 1))
	return &out
}

// Right child of x
func Right(x NodeIndex, n LeafCount) *NodeIndex {
	if level(x) == 0 {
		return nil
	}

	w := NodeIndex(NodeWidth(n))
	r := x ^ (0x03 << (level(x) - 1))
	for r >= w {
		r = *Left(r)
	}
	return &r
}

// Immediate parent of x; may not exist in tree
func parent_step(x NodeIndex) NodeIndex {
	// xy01 -> x011
	k := level(x)
	one := uint(1)
	return NodeIndex((uint(x) | (one << k)) & ^(one << (k + 1)))
}

// Parent of x
func Parent(x NodeIndex, n LeafCount) *NodeIndex {
	// root's parent is itself
	if x == Root(n) {
		return nil
	}

	w := NodeIndex(NodeWidth(n))
	p := parent_step(x)
	for p >= w {
		p = parent_step(p)
	}
	return &p
}

// Sibling of x
func Sibling(x NodeIndex, n LeafCount) *NodeIndex {
	p := Parent(x, n)
	switch {
	case p == nil: // root
		return nil

	case x < *p: // left child
		return Right(*p, n)

	case x > *p: // right child
		return Left(*p)
	}

	panic("Invalid parent calculation")
}
