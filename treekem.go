package mls

import (
	"fmt"

	"github.com/cisco/go-tls-syntax"
)

type TreeKEMPathStep struct {
	PublicKey            HPKEPublicKey
	EncryptedPathSecrets map[NodeIndex]HPKECiphertext `tls:"head=4"`
}

type TreeKEMPath struct {
	LeafKeyPackage KeyPackage
	Steps          []TreeKEMPathStep `tls:"head=4"`
}

// This produces a list of parent hashes that are off by one with respect to the
// steps in the path.  The path hash at position i goes with the public key at
// position i-1, and the path hash at position 0 goes in the leaf.
func (path TreeKEMPath) ParentHashes(suite CipherSuite) ([][]byte, error) {
	ph := make([][]byte, len(path.Steps))

	var err error
	var lastHash []byte
	for i := len(path.Steps) - 1; i > 0; i-- {
		parentNode := ParentNode{
			PublicKey:  path.Steps[i+1].PublicKey,
			ParentHash: lastHash,
		}

		lastHash, err = syntax.Marshal(parentNode)
		if err != nil {
			return nil, err
		}

		ph[i] = dup(lastHash)
	}

	return ph, nil
}

func (path *TreeKEMPath) Sign(suite CipherSuite, initPub HPKEPublicKey, sigPriv SignaturePrivateKey, opts *KeyPackageOpts) error {
	// Compute parent hashes down the tree from the root
	leafParentHash := []byte(nil)
	if len(path.Steps) > 0 {
		ph, err := path.ParentHashes(suite)
		if err != nil {
			return err
		}

		leafParentHash = ph[0]
	}

	// Re-sign the leaf key package
	// TODO(RLB) Apply any options from opts
	phe := ParentHashExtension{leafParentHash}
	err := path.LeafKeyPackage.SetExtensions([]ExtensionBody{phe})
	if err != nil {
		return err
	}

	path.LeafKeyPackage.InitKey = initPub

	return path.LeafKeyPackage.Sign(sigPriv)
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

type TreeKEMPrivateKey struct {
	Suite       CipherSuite
	Index       LeafIndex
	PathSecrets map[NodeIndex][]byte
	PrivateKeys map[NodeIndex]HPKEPrivateKey
}

func NewTreeKEMPrivateKeyForJoiner(suite CipherSuite, index LeafIndex, size LeafCount, leafSecret []byte, intersect NodeIndex, pathSecret []byte) (*TreeKEMPrivateKey, error) {
	priv := &TreeKEMPrivateKey{
		Suite:       suite,
		Index:       index,
		PathSecrets: map[NodeIndex][]byte{},
		PrivateKeys: map[NodeIndex]HPKEPrivateKey{},
	}

	var err error
	ni := toNodeIndex(index)
	priv.PathSecrets[ni] = dup(pathSecret)
	priv.PrivateKeys[ni], err = priv.Suite.hpke().Derive(leafSecret)
	if err != nil {
		return nil, err
	}

	err = priv.setPathSecrets(intersect, size, pathSecret)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func NewTreeKEMPrivateKey(suite CipherSuite, size LeafCount, index LeafIndex, leafSecret []byte) (*TreeKEMPrivateKey, error) {
	priv := &TreeKEMPrivateKey{
		Suite:       suite,
		Index:       index,
		PathSecrets: map[NodeIndex][]byte{},
		PrivateKeys: map[NodeIndex]HPKEPrivateKey{},
	}

	err := priv.setPathSecrets(toNodeIndex(index), size, leafSecret)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func (priv TreeKEMPrivateKey) pathStep(pathSecret []byte) []byte {
	return priv.Suite.hkdfExpandLabel(pathSecret, "path", []byte{}, priv.Suite.Constants().SecretSize)
}

func (priv *TreeKEMPrivateKey) setPathSecrets(start NodeIndex, size LeafCount, secret []byte) error {
	r := root(size)
	pathSecret := secret
	var err error
	for n := start; n != r; n = parent(n, size) {
		priv.PathSecrets[n] = dup(pathSecret)
		priv.PrivateKeys[n], err = priv.Suite.hpke().Derive(pathSecret)
		if err != nil {
			return err
		}

		pathSecret = priv.pathStep(pathSecret)
	}

	priv.PathSecrets[r] = dup(pathSecret)
	priv.PrivateKeys[r], err = priv.Suite.hpke().Derive(pathSecret)

	return nil
}

func (priv TreeKEMPrivateKey) PathSecret(to LeafIndex) (NodeIndex, []byte, error) {
	n := ancestor(priv.Index, to)
	secret, ok := priv.PathSecrets[n]
	if !ok {
		return 0, nil, fmt.Errorf("Path secret not found for node %d", n)
	}

	return n, secret, nil
}

func (priv TreeKEMPrivateKey) Decap(from LeafIndex, size LeafCount, context []byte, path TreeKEMPath) (*TreeKEMPrivateKey, error) {
	// Decrypt a path secret
	ancestor, iPath := ancestorIndex(priv.Index, from, size)

	var err error
	var pathSecret []byte
	for n, ct := range path.Steps[iPath].EncryptedPathSecrets {
		if nodePriv, ok := priv.PrivateKeys[n]; ok {
			pathSecret, err = priv.Suite.hpke().Decrypt(nodePriv, context, ct)
			if err != nil {
				return nil, err
			}
		}
	}

	if pathSecret == nil {
		return nil, fmt.Errorf("Unable to decrypt path secret")
	}

	// Clone and hash toward the root
	out := &TreeKEMPrivateKey{
		Suite:       priv.Suite,
		Index:       priv.Index,
		PathSecrets: map[NodeIndex][]byte{},
		PrivateKeys: map[NodeIndex]HPKEPrivateKey{},
	}

	err = out.setPathSecrets(ancestor, size, pathSecret)
	if err != nil {
		return nil, err
	}

	// TODO Check the accuracy of the public keys in the path

	// Copy in the private values not overwritten
	for n := range priv.PathSecrets {
		if _, ok := out.PathSecrets[n]; ok {
			continue
		}

		out.PathSecrets[n] = priv.PathSecrets[n]
		out.PrivateKeys[n] = priv.PrivateKeys[n]
	}

	return out, nil
}

func (priv TreeKEMPrivateKey) dump(label string) {
	fmt.Printf("=== %s ===\n", label)
	fmt.Printf("suite=[%d] index=[%d]\n", priv.Suite, priv.Index)
	for n, nodePriv := range priv.PrivateKeys {
		pub := nodePriv.PublicKey.Data[:4]
		fmt.Printf("  [%d] %x...\n", n, pub)
	}
}

func (priv TreeKEMPrivateKey) Consistent(pub TreeKEMPublicKey) bool {
	if priv.Suite != pub.Suite {
		fmt.Printf("Different suites %d %d \n", priv.Suite, pub.Suite)
		return false
	}

	for n, nodePriv := range priv.PrivateKeys {
		if pub.Nodes[n].Blank() {
			return false
		}

		lhs := nodePriv.PublicKey
		rhs := pub.Nodes[n].Node.PublicKey()

		if pub.Nodes[n].Blank() || !lhs.Equals(rhs) {
			fmt.Printf("difference at node %d %x %x\n", n, lhs.Data, rhs.Data)
			return false
		}
	}

	return true
}

////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////

type TreeKEMPublicKey struct {
	Suite CipherSuite    `tls:"omit"`
	Nodes []OptionalNode `tls:"head=4"`
}

func NewTreeKEMPublicKey(suite CipherSuite) *TreeKEMPublicKey {
	return &TreeKEMPublicKey{Suite: suite}
}

func (pub *TreeKEMPublicKey) AddLeaf(keyPkg KeyPackage) LeafIndex {
	// Find the leftmost free leaf
	index := LeafIndex(0)
	size := LeafIndex(pub.Size())
	for index < size && !pub.Nodes[toNodeIndex(index)].Blank() {
		index++
	}

	// Extend the tree if necessary
	n := toNodeIndex(index)
	for len(pub.Nodes) < int(n)+1 {
		pub.Nodes = append(pub.Nodes, OptionalNode{})
	}

	pub.Nodes[n] = newLeafNode(keyPkg)

	// update unmerged list
	dp := dirpath(n, pub.Size())
	for _, v := range dp {
		if v == toNodeIndex(index) || pub.Nodes[v].Node == nil {
			continue
		}
		pub.Nodes[v].Node.Parent.AddUnmerged(index)
	}

	pub.clearHashPath(index)
	return index
}

func (pub *TreeKEMPublicKey) UpdateLeaf(index LeafIndex, keyPkg KeyPackage) {
	pub.BlankPath(index)
	pub.Nodes[toNodeIndex(index)] = newLeafNode(keyPkg)
	pub.clearHashPath(index)
}

func (pub *TreeKEMPublicKey) BlankPath(index LeafIndex) {
	if len(pub.Nodes) == 0 {
		return
	}

	ni := toNodeIndex(index)

	pub.Nodes[ni].SetToBlank()

	for _, n := range dirpath(ni, pub.Size()) {
		pub.Nodes[n].SetToBlank()
	}
}

type KeyPackageOpts struct {
	// TODO New credential
	// TODO Extensions
}

func (pub TreeKEMPublicKey) Encap(from LeafIndex, context, leafSecret []byte, leafSigPriv SignaturePrivateKey, opts *KeyPackageOpts) (*TreeKEMPrivateKey, *TreeKEMPath, error) {
	// Generate path secrets and private keys
	priv, err := NewTreeKEMPrivateKey(pub.Suite, pub.Size(), from, leafSecret)
	if err != nil {
		return nil, nil, err
	}

	// Package into a TreeKEMPath
	dp := dirpath(toNodeIndex(from), pub.Size())
	path := &TreeKEMPath{
		LeafKeyPackage: *pub.Nodes[toNodeIndex(from)].Node.Leaf,
		Steps:          make([]TreeKEMPathStep, len(dp)),
	}
	for i, n := range dp {
		path.Steps[i] = TreeKEMPathStep{
			PublicKey:            priv.PrivateKeys[n].PublicKey,
			EncryptedPathSecrets: map[NodeIndex]HPKECiphertext{},
		}

		pathSecret := priv.PathSecrets[n]
		for _, nr := range pub.resolve(n) {
			nodePub := pub.Nodes[nr].Node.PublicKey()
			path.Steps[i].EncryptedPathSecrets[nr], err = pub.Suite.hpke().Encrypt(nodePub, context, pathSecret)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	// Sign the TreeKEMPath
	leafInitPub := priv.PrivateKeys[toNodeIndex(from)].PublicKey
	err = path.Sign(pub.Suite, leafInitPub, leafSigPriv, opts)
	if err != nil {
		return nil, nil, err
	}

	return priv, path, nil
}

func (pub *TreeKEMPublicKey) Merge(from LeafIndex, path TreeKEMPath) error {
	ni := toNodeIndex(from)
	pub.Nodes[ni] = newLeafNode(path.LeafKeyPackage)

	dp := dirpath(ni, pub.Size())
	if len(dp) != len(path.Steps) {
		return fmt.Errorf("Malformed TreeKEMPath %d %d", len(dp), len(path.Steps))
	}

	for i, n := range dp {
		pub.Nodes[n] = newParentNodeFromPublicKey(path.Steps[i].PublicKey)
	}

	return nil
}

func (pub TreeKEMPublicKey) Size() LeafCount {
	return leafWidth(nodeCount(len(pub.Nodes)))
}

func (pub TreeKEMPublicKey) Clone() TreeKEMPublicKey {
	next := TreeKEMPublicKey{
		Suite: pub.Suite,
		Nodes: make([]OptionalNode, len(pub.Nodes)),
	}

	for i, n := range pub.Nodes {
		next.Nodes[i] = n.Clone()
	}

	return next
}

func (pub TreeKEMPublicKey) Equals(o TreeKEMPublicKey) bool {
	if len(pub.Nodes) != len(o.Nodes) {
		return false
	}

	for i := 0; i < len(pub.Nodes); i++ {
		if !pub.Nodes[i].Node.Equals(o.Nodes[i].Node) {
			return false
		}
	}
	return true
}

func (pub TreeKEMPublicKey) Find(kp KeyPackage) (LeafIndex, bool) {
	num := pub.Size()
	for i := LeafIndex(0); LeafCount(i) < num; i++ {
		ni := toNodeIndex(i)
		n := pub.Nodes[ni]
		if n.Blank() {
			continue
		}

		if n.Node.Leaf.Equals(kp) {
			return i, true
		}
	}

	return 0, false
}

func (pub TreeKEMPublicKey) resolve(index NodeIndex) []NodeIndex {
	// Resolution of non-blank is node + unmerged leaves
	if !pub.Nodes[index].Blank() {
		res := []NodeIndex{index}
		if level(index) > 0 {
			for _, v := range pub.Nodes[index].Node.Parent.UnmergedLeaves {
				res = append(res, toNodeIndex(v))
			}
		}
		return res
	}

	// Resolution of blank leaf is the empty list
	if level(index) == 0 {
		return []NodeIndex{}
	}

	// Resolution of blank intermediate node is concatenation of the resolutions
	// of the children
	l := pub.resolve(left(index))
	r := pub.resolve(right(index, pub.Size()))
	l = append(l, r...)
	return l
}

func (pub *TreeKEMPublicKey) clearHashPath(index LeafIndex) {
	ni := toNodeIndex(index)
	pub.Nodes[ni].Hash = nil

	for _, n := range dirpath(ni, pub.Size()) {
		pub.Nodes[n].Hash = nil
	}
}

func (pub TreeKEMPublicKey) RootHash() []byte {
	r := root(pub.Size())
	return pub.Nodes[r].Hash
}

func (pub *TreeKEMPublicKey) setHash(index NodeIndex) error {
	if level(index) == 0 {
		return pub.Nodes[index].SetLeafNodeHash(pub.Suite, toLeafIndex(index))
	}

	li := left(index)
	lh := pub.Nodes[li].Hash
	if lh == nil {
		if err := pub.setHash(li); err != nil {
			return err
		}
	}

	ri := right(index, pub.Size())
	rh := pub.Nodes[ri].Hash
	if rh == nil {
		if err := pub.setHash(ri); err != nil {
			return err
		}
	}

	return pub.Nodes[index].SetParentNodeHash(pub.Suite, index, lh, rh)
}

func (pub TreeKEMPublicKey) dump(label string) {
	fmt.Printf("~~~ %s ~~~\n", label)
	fmt.Printf("suite=[%d]\n", pub.Suite)

	for i, n := range pub.Nodes {
		if n.Blank() {
			fmt.Printf("  [%d] _\n", i)
			continue
		}

		pub := n.Node.PublicKey().Data[:4]
		fmt.Printf("  [%d] %x...\n", i, pub)
	}
}
