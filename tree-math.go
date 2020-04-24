package mls

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
type nodeCount uint32

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
func nodeWidth(n LeafCount) nodeCount {
	return nodeCount(2*n - 1)
}

// Number of leaves for a tree with N nodes
func leafWidth(n nodeCount) LeafCount {
	return LeafCount((n + 1) >> 1)
}

// Index of the root of the tree with N leaves
func root(n LeafCount) NodeIndex {
	w := nodeWidth(n)
	return NodeIndex((1 << log2(w)) - 1)
}

// Left child of x
func left(x NodeIndex) NodeIndex {
	if level(x) == 0 {
		return x
	}

	return x ^ (0x01 << (level(x) - 1))
}

// Right child of x
func right(x NodeIndex, n LeafCount) NodeIndex {
	if level(x) == 0 {
		return x
	}

	w := NodeIndex(nodeWidth(n))
	r := x ^ (0x03 << (level(x) - 1))
	for r >= w {
		r = left(r)
	}
	return r
}

// Immediate parent of x; may not exist in tree
func parent_step(x NodeIndex) NodeIndex {
	// xy01 -> x011
	k := level(x)
	one := uint(1)
	return NodeIndex((uint(x) | (one << k)) & ^(one << (k + 1)))
}

// Parent of x
func parent(x NodeIndex, n LeafCount) NodeIndex {
	// root's parent is itself
	if x == root(n) {
		return x
	}

	w := NodeIndex(nodeWidth(n))
	p := parent_step(x)
	for p >= w {
		p = parent_step(p)
	}
	return p
}

// Sibling of x
func sibling(x NodeIndex, n LeafCount) NodeIndex {
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
// Ordered from leaf to root, excluding leaf, including root
func dirpath(x NodeIndex, n LeafCount) []NodeIndex {
	d := []NodeIndex{}
	p := parent(x, n)
	r := root(n)
	for p != r {
		d = append(d, p)
		p = parent(p, n)
	}

	if x != r {
		d = append(d, p)
	}
	return d
}

// Copath for x
// Ordered from leaf to root
func copath(x NodeIndex, n LeafCount) []NodeIndex {
	d := dirpath(x, n)
	if len(d) == 0 {
		return []NodeIndex{}
	}

	d = append([]NodeIndex{x}, d[:len(d)-1]...)

	r := root(n)
	c := make([]NodeIndex, len(d))
	for i, x := range d {
		// Don't include the root
		if x == r {
			continue
		}

		c[i] = sibling(x, n)
	}

	return c
}

func inPath(x, y NodeIndex) bool {
	lx, ly := level(x), level(y)
	return lx <= ly && x>>(ly+1) == y>>(ly+1)
}

func fullAncestor(l, r NodeIndex) NodeIndex {
	ll, lr := level(l)+1, level(r)+1
	if ll <= lr && l>>lr == r>>lr {
		return r
	}
	if lr <= ll && l>>ll == r>>ll {
		return l
	}

	k := uint(0)
	ln, rn := l, r
	for ln != rn {
		ln, rn = ln>>1, rn>>1
		k += 1
	}

	return (ln << k) + (1 << (k - 1)) - 1
}

// Common ancestor of two leaves
func ancestor(l, r LeafIndex) NodeIndex {
	ln, rn := toNodeIndex(l), toNodeIndex(r)

	k := uint(0)
	for ln != rn {
		ln, rn = ln>>1, rn>>1
		k += 1
	}

	return (ln << k) + (1 << (k - 1)) - 1
}
