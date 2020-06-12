package mls

import (
	"bytes"
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
	for i := len(path.Steps) - 1; i >= 0; i-- {
		parentNode := ParentNode{
			PublicKey:  path.Steps[i].PublicKey,
			ParentHash: lastHash,
		}

		lastHash, err = syntax.Marshal(parentNode)
		if err != nil {
			return nil, err
		}

		ph[i] = suite.Digest(lastHash)
	}

	return ph, nil
}

func (path TreeKEMPath) ParentHashValid(suite CipherSuite) error {
	leafParentHash := []byte{}
	if len(path.Steps) > 0 {
		ph, err := path.ParentHashes(suite)
		if err != nil {
			return err
		}

		leafParentHash = ph[0]
	}

	phe := ParentHashExtension{}
	found, err := path.LeafKeyPackage.Extensions.Find(&phe)
	switch {
	case err != nil:
		return err

	case !found:
		return fmt.Errorf("No ParentHash extension")

	case !bytes.Equal(leafParentHash, phe.ParentHash):
		return fmt.Errorf("Incorrect parent hash")
	}

	return nil
}

type KeyPackageOpts struct {
	// TODO New credential
	// TODO Extensions
}

func (path *TreeKEMPath) Sign(suite CipherSuite, initPub HPKEPublicKey, sigPriv SignaturePrivateKey, opts *KeyPackageOpts) error {
	// Compute parent hashes down the tree from the root
	leafParentHash := []byte{}
	if len(path.Steps) > 0 {
		ph, err := path.ParentHashes(suite)
		if err != nil {
			return err
		}

		leafParentHash = ph[0]
	}

	// Re-sign the leaf key package
	// TODO(RLB) Apply any options from opts
	// TODO(RLB) Move resigning logic into KeyPackage
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
	Suite           CipherSuite
	Index           LeafIndex
	UpdateSecret    []byte                       `tls:"head=1"`
	PathSecrets     map[NodeIndex]Bytes1         `tls:"head=4"`
	privateKeyCache map[NodeIndex]HPKEPrivateKey `tls:"omit"`
}

func NewTreeKEMPrivateKeyForJoiner(suite CipherSuite, index LeafIndex, size LeafCount, leafSecret []byte, intersect NodeIndex, pathSecret []byte) *TreeKEMPrivateKey {
	priv := &TreeKEMPrivateKey{
		Suite:           suite,
		Index:           index,
		PathSecrets:     map[NodeIndex]Bytes1{},
		privateKeyCache: map[NodeIndex]HPKEPrivateKey{},
	}

	priv.PathSecrets[toNodeIndex(index)] = dup(leafSecret)
	priv.setPathSecrets(intersect, size, pathSecret)
	return priv
}

func NewTreeKEMPrivateKey(suite CipherSuite, size LeafCount, index LeafIndex, leafSecret []byte) *TreeKEMPrivateKey {
	priv := &TreeKEMPrivateKey{
		Suite:           suite,
		Index:           index,
		PathSecrets:     map[NodeIndex]Bytes1{},
		privateKeyCache: map[NodeIndex]HPKEPrivateKey{},
	}

	priv.setPathSecrets(toNodeIndex(index), size, leafSecret)
	return priv
}

func (priv TreeKEMPrivateKey) pathStep(pathSecret []byte) []byte {
	return priv.Suite.hkdfExpandLabel(pathSecret, "path", []byte{}, priv.Suite.Constants().SecretSize)
}

func (priv *TreeKEMPrivateKey) setPathSecrets(start NodeIndex, size LeafCount, secret []byte) {
	r := root(size)
	pathSecret := secret
	for n := start; n != r; n = parent(n, size) {
		priv.PathSecrets[n] = dup(pathSecret)
		delete(priv.privateKeyCache, n)
		pathSecret = priv.pathStep(pathSecret)
	}

	priv.PathSecrets[r] = dup(pathSecret)
	delete(priv.privateKeyCache, r)

	priv.UpdateSecret = priv.pathStep(pathSecret)
}

func (priv TreeKEMPrivateKey) privateKey(n NodeIndex) (HPKEPrivateKey, error) {
	if key, ok := priv.privateKeyCache[n]; ok {
		return key, nil
	}

	secret, ok := priv.PathSecrets[n]
	if !ok || secret == nil {
		return HPKEPrivateKey{}, fmt.Errorf("Private key not found")
	}

	key, err := priv.Suite.hpke().Derive(secret)
	if err != nil {
		return HPKEPrivateKey{}, err
	}

	priv.privateKeyCache[n] = key
	return key, nil
}

func (priv TreeKEMPrivateKey) SharedPathSecret(to LeafIndex) (NodeIndex, []byte, bool) {
	n := ancestor(priv.Index, to)
	secret, ok := priv.PathSecrets[n]
	return n, secret, ok
}

func (priv *TreeKEMPrivateKey) SetLeafSecret(secret []byte) {
	// TODO(RLB) Check for consistency?
	ni := toNodeIndex(priv.Index)
	priv.PathSecrets[ni] = dup(secret)
	delete(priv.privateKeyCache, ni)
}

func (priv *TreeKEMPrivateKey) Decap(from LeafIndex, size LeafCount, context []byte, path TreeKEMPath) error {
	// Decrypt a path secret
	ancestor, iPath := ancestorIndex(priv.Index, from, size)

	var pathSecret []byte
	for n, ct := range path.Steps[iPath].EncryptedPathSecrets {
		if _, ok := priv.PathSecrets[n]; ok {
			nodePriv, err := priv.privateKey(n)
			if err != nil {
				return err
			}

			pathSecret, err = priv.Suite.hpke().Decrypt(nodePriv, context, ct)
			if err != nil {
				return err
			}
		}
	}

	if pathSecret == nil {
		return fmt.Errorf("Unable to decrypt path secret")
	}

	// TODO Check the accuracy of the public keys in the path

	// Hash toward the root
	priv.setPathSecrets(ancestor, size, pathSecret)
	return nil
}

func (priv TreeKEMPrivateKey) Clone() TreeKEMPrivateKey {
	out := TreeKEMPrivateKey{
		Suite:           priv.Suite,
		Index:           priv.Index,
		PathSecrets:     map[NodeIndex]Bytes1{},
		privateKeyCache: map[NodeIndex]HPKEPrivateKey{},
	}

	for n := range priv.PathSecrets {
		out.PathSecrets[n] = priv.PathSecrets[n]
	}

	for n := range priv.privateKeyCache {
		out.privateKeyCache[n] = priv.privateKeyCache[n]
	}

	return out
}

func (priv TreeKEMPrivateKey) dump(label string) {
	fmt.Printf("=== %s ===\n", label)
	fmt.Printf("suite=[%d] index=[%d]\n", priv.Suite, priv.Index)
	fmt.Printf("update=[%x]\n", priv.UpdateSecret)
	for n := range priv.PathSecrets {
		nodePriv, err := priv.privateKey(n)
		if err != nil {
			panic(err)
		}

		secret := priv.PathSecrets[n]
		pub := nodePriv.PublicKey.Data
		fmt.Printf("  [%d] secret=%x... pub=%x...\n", n, secret, pub)
	}
}

func (priv TreeKEMPrivateKey) Consistent(other TreeKEMPrivateKey) bool {
	if priv.Suite != other.Suite {
		return false
	}

	if !bytes.Equal(priv.UpdateSecret, other.UpdateSecret) {
		return false
	}

	overlap := map[NodeIndex]bool{}
	for n := range priv.PathSecrets {
		if _, ok := other.PathSecrets[n]; ok {
			overlap[n] = true
		}
	}
	if len(overlap) == 0 {
		return false
	}

	for n := range overlap {
		if !bytes.Equal(priv.PathSecrets[n], other.PathSecrets[n]) {
			return false
		}
	}

	return true
}

func (priv TreeKEMPrivateKey) ConsistentPub(pub TreeKEMPublicKey) bool {
	if priv.Suite != pub.Suite {
		return false
	}

	for n := range priv.PathSecrets {
		nodePriv, err := priv.privateKey(n)
		if err != nil {
			return false
		}

		if pub.Nodes[n].Blank() {
			return false
		}

		lhs := nodePriv.PublicKey
		rhs := pub.Nodes[n].Node.PublicKey()

		if pub.Nodes[n].Blank() || !lhs.Equals(rhs) {
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

func (pub TreeKEMPublicKey) Encap(from LeafIndex, context, leafSecret []byte, leafSigPriv SignaturePrivateKey, opts *KeyPackageOpts) (*TreeKEMPrivateKey, *TreeKEMPath, error) {
	// Generate path secrets
	priv := NewTreeKEMPrivateKey(pub.Suite, pub.Size(), from, leafSecret)

	// Package into a TreeKEMPath
	dp := dirpath(toNodeIndex(from), pub.Size())
	path := &TreeKEMPath{
		LeafKeyPackage: *pub.Nodes[toNodeIndex(from)].Node.Leaf,
		Steps:          make([]TreeKEMPathStep, len(dp)),
	}
	for i, n := range dp {
		nodePriv, err := priv.privateKey(n)
		if err != nil {
			return nil, nil, err
		}

		path.Steps[i] = TreeKEMPathStep{
			PublicKey:            nodePriv.PublicKey,
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
	leafPriv, err := priv.privateKey(toNodeIndex(from))
	if err != nil {
		return nil, nil, err
	}

	err = path.Sign(pub.Suite, leafPriv.PublicKey, leafSigPriv, opts)
	if err != nil {
		return nil, nil, err
	}

	// Update the public key itself
	err = pub.Merge(from, *path)
	if err != nil {
		return nil, nil, err
	}

	// XXX(RLB): Should be possible to make a more targeted change, e.g., clearHashPath(from)
	pub.clearHashAll()
	pub.SetHashAll()
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

	// XXX(RLB): Should be possible to make a more targeted change, e.g., clearHashPath(from)
	pub.clearHashAll()
	pub.SetHashAll()
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

func (pub TreeKEMPublicKey) KeyPackage(index LeafIndex) (KeyPackage, bool) {
	ni := toNodeIndex(index)
	if pub.Nodes[ni].Blank() {
		return KeyPackage{}, false
	}

	return *pub.Nodes[ni].Node.Leaf, true
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

func (pub *TreeKEMPublicKey) clearHashAll() {
	for n := range pub.Nodes {
		pub.Nodes[n].Hash = nil
	}
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

func (pub *TreeKEMPublicKey) SetHashAll() error {
	return pub.setHash(root(pub.Size()))
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
		hash := "-"
		if n.Hash != nil {
			hash = fmt.Sprintf("%x", n.Hash[:4])
		}

		if n.Blank() {
			fmt.Printf("  [%d] <%s> _\n", i, hash)
			continue
		}

		pub := n.Node.PublicKey().Data[:4]
		fmt.Printf("  [%d] <%s> %x...\n", i, hash, pub)
	}
}
