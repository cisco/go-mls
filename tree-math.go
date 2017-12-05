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

// Position of the most significant 1 bit
func log2(x uint) uint {
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
func level(x uint) uint {
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
func nodeWidth(n uint) uint {
	return 2*(n-1) + 1
}

// Index of the root of the tree with N leaves
func root(n uint) uint {
	w := nodeWidth(n)
	return uint((1 << log2(w)) - 1)
}

// Left child of x
func left(x uint) uint {
	if level(x) == 0 {
		return x
	}

	return x ^ (0x01 << (level(x) - 1))
}

// Right child of x
func right(x uint, n uint) uint {
	if level(x) == 0 {
		return x
	}

	r := x ^ (0x03 << (level(x) - 1))
	for r > 2*(n-1) {
		r = left(r)
	}
	return r
}

// Immediate parent of x; may not exist in tree
func parent_step(x uint) uint {
	// xy01 -> x011
	k := level(x)
	one := uint(1)
	return (x | (one << k)) & ^(one << (k + 1))
}

// Parent of x
func parent(x uint, n uint) uint {
	// root's parent is itself
	if x == root(n) {
		return x
	}

	p := parent_step(x)
	for p > 2*(n-1) {
		p = parent_step(p)
	}
	return p
}

// Sibling of x
func sibling(x uint, n uint) uint {
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
// Ordered from root to leaf, excluding leaf and root
func dirpath(x uint, n uint) []uint {
	d := []uint{}
	p := parent(x, n)
	r := root(n)
	for p != r {
		d = append([]uint{p}, d...)
		p = parent(p, n)
	}
	return d
}

// Copath for x
// Ordered from root to leaf
func copath(x uint, n uint) []uint {
	d := dirpath(x, n)

	// Add leaf, which is missing from direct path
	if x != sibling(x, n) {
		d = append(d, x)
	}

	c := make([]uint, len(d))
	for i, x := range d {
		c[i] = sibling(x, n)
	}

	return c
}

// Number of leaves under a node
func subtreeSize(x uint, n uint) uint {
	w := nodeWidth(n)
	lr := uint((1 << level(x)) - 1)
	rr := uint(lr)
	if x+rr >= w {
		rr = w - x - 1
	}

	return (lr+rr)/2 + 1
}

// Array of frontier heads
func frontier(n uint) []uint {
	if n == 0 {
		return []uint{}
	}

	r := root(n)
	s := subtreeSize(r, n)
	f := []uint{}
	for s != (1 << log2(s)) {
		l := left(r)
		r = right(r, n)
		s = subtreeSize(r, n)
		f = append(f, l)
	}
	f = append(f, r)
	return f
}
