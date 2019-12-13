package mls

import "fmt"

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

type leafIndex uint32
type leafCount uint32
type nodeIndex uint32
type nodeCount uint32

func toNodeIndex(leaf leafIndex) nodeIndex {
	return nodeIndex(2 * leaf)
}

// Position of the most significant 1 bit
func log2(x nodeCount) uint {
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
func level(x nodeIndex) uint {
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
func nodeWidth(n leafCount) nodeCount {
	return nodeCount(2*(n-1) + 1)
}

// Index of the root of the tree with N leaves
func root(n leafCount) nodeIndex {
	w := nodeWidth(n)
	return nodeIndex((1 << log2(w)) - 1)
}

// Left child of x
func left(x nodeIndex) nodeIndex {
	if level(x) == 0 {
		return x
	}

	return x ^ (0x01 << (level(x) - 1))
}

// Right child of x
func right(x nodeIndex, n leafCount) nodeIndex {
	if level(x) == 0 {
		return x
	}

	w := nodeIndex(nodeWidth(n))
	r := x ^ (0x03 << (level(x) - 1))
	for r >= w {
		r = left(r)
	}
	return r
}

// Immediate parent of x; may not exist in tree
func parent_step(x nodeIndex) nodeIndex {
	// xy01 -> x011
	k := level(x)
	one := uint(1)
	return nodeIndex((uint(x) | (one << k)) & ^(one << (k + 1)))
}

// Parent of x
func parent(x nodeIndex, n leafCount) nodeIndex {
	// root's parent is itself
	if x == root(n) {
		return x
	}

	w := nodeIndex(nodeWidth(n))
	p := parent_step(x)
	for p >= w {
		p = parent_step(p)
	}
	return p
}

// Sibling of x
func sibling(x nodeIndex, n leafCount) nodeIndex {
	p := parent(x, n)
	if x < p {
		return right(p, n)
	} else if x > p {
		return left(p)
	}

	// root's sibling is itself
	return p
}

// Direct path for x
// Ordered from leaf to root, including leaf and root
func dirpath(x nodeIndex, n leafCount) []nodeIndex {
	d := []nodeIndex{}
	p := x
	r := root(n)
	for p != r {
		d = append(d, p)
		p = parent(p, n)
	}

	d = append(d, p)
	return d
}

// Copath for x
// Ordered from leaf to root
func copath(x nodeIndex, n leafCount) []nodeIndex {
	d := dirpath(x, n)

	r := root(n)
	c := make([]nodeIndex, len(d)-1)
	for i, x := range d {
		// Don't include the root
		if x == r {
			continue
		}

		c[i] = sibling(x, n)
	}

	return c
}

func numLeaves(c nodeCount) leafCount {
	if c == 0 {
		return 0
	}

	if c&1 == 0 {
		panic(fmt.Errorf("only odd node counts describe trees"))
	}
	return leafCount((c >> 1) + 1)
}
