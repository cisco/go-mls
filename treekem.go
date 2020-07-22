package mls

import (
	"bytes"
	"fmt"
	"reflect"

	syntax "github.com/cisco/go-tls-syntax"
)

type NodeType uint8

const (
	NodeTypeLeaf   NodeType = 0x00
	NodeTypeParent NodeType = 0x01
)

///
/// ParentNode
///

type ParentNode struct {
	PublicKey      HPKEPublicKey
	UnmergedLeaves []LeafIndex `tls:"head=4"`
	ParentHash     []byte      `tls:"head=1"`
}

func (n *ParentNode) Equals(other *ParentNode) bool {
	pubKey := reflect.DeepEqual(n.PublicKey, other.PublicKey)
	unmerged := reflect.DeepEqual(n.UnmergedLeaves, other.UnmergedLeaves)
	parentHash := reflect.DeepEqual(n.ParentHash, other.ParentHash)

	return pubKey && unmerged && parentHash
}

func (n ParentNode) Clone() ParentNode {
	next := ParentNode{
		PublicKey:      n.PublicKey,
		UnmergedLeaves: make([]LeafIndex, len(n.UnmergedLeaves)),
		ParentHash:     dup(n.ParentHash),
	}

	for i, n := range n.UnmergedLeaves {
		next.UnmergedLeaves[i] = n
	}

	return next
}

func (n *ParentNode) AddUnmerged(l LeafIndex) {
	n.UnmergedLeaves = append(n.UnmergedLeaves, l)
}

///
/// Node
///
type Node struct {
	Leaf   *KeyPackage
	Parent *ParentNode
}

func (n *Node) Equals(other *Node) bool {
	if n == nil || other == nil {
		return n == other
	}

	switch n.Type() {
	case NodeTypeLeaf:
		return n.Leaf.Equals(*other.Leaf)
	case NodeTypeParent:
		return n.Parent.Equals(other.Parent)
	default:
		return false
	}
}

func (n *Node) Clone() *Node {
	if n == nil {
		return nil
	}

	next := &Node{}
	switch n.Type() {
	case NodeTypeLeaf:
		clone := n.Leaf.Clone()
		next.Leaf = &clone
	case NodeTypeParent:
		clone := n.Parent.Clone()
		next.Parent = &clone
	default:
		panic("Malformed node")
	}

	return next
}

func (n Node) Type() NodeType {
	switch {
	case n.Leaf != nil:
		return NodeTypeLeaf
	case n.Parent != nil:
		return NodeTypeParent
	default:
		panic("Malformed node")
	}
}

func (n Node) PublicKey() HPKEPublicKey {
	switch n.Type() {
	case NodeTypeLeaf:
		return n.Leaf.InitKey
	case NodeTypeParent:
		return n.Parent.PublicKey
	default:
		panic("Malformed node")
	}
}

func (n Node) MarshalTLS() ([]byte, error) {
	s := syntax.NewWriteStream()
	nodeType := n.Type()
	err := s.Write(nodeType)
	if err != nil {
		return nil, err
	}

	switch nodeType {
	case NodeTypeLeaf:
		err = s.Write(n.Leaf)
	case NodeTypeParent:
		err = s.Write(n.Parent)
	default:
		err = fmt.Errorf("mls.node: Invalid node type")
	}
	if err != nil {
		return nil, err
	}

	return s.Data(), nil
}

func (n *Node) UnmarshalTLS(data []byte) (int, error) {
	s := syntax.NewReadStream(data)
	var nodeType NodeType
	_, err := s.Read(&nodeType)
	if err != nil {
		return 0, err
	}

	switch nodeType {
	case NodeTypeLeaf:
		n.Leaf = new(KeyPackage)
		_, err = s.Read(n.Leaf)
	case NodeTypeParent:
		n.Parent = new(ParentNode)
		_, err = s.Read(n.Parent)
	default:
		err = fmt.Errorf("mls.node: Invalid node type")
	}
	if err != nil {
		return 0, err
	}

	return s.Position(), nil
}

///
/// OptionalNode
///
type OptionalNode struct {
	Node *Node  `tls:"optional"`
	Hash []byte `tls:"omit"`
}

func newLeafNode(keyPkg KeyPackage) OptionalNode {
	return OptionalNode{Node: &Node{Leaf: &keyPkg}}
}

func newParentNode(pub HPKEPublicKey) OptionalNode {
	parentNode := &ParentNode{
		PublicKey:      pub,
		UnmergedLeaves: []LeafIndex{},
		ParentHash:     []byte{},
	}
	return OptionalNode{Node: &Node{Parent: parentNode}}
}

func (n OptionalNode) Clone() OptionalNode {
	return OptionalNode{
		Node: n.Node.Clone(),
		Hash: dup(n.Hash),
	}
}

func (n OptionalNode) Blank() bool {
	return n.Node == nil
}

func (n *OptionalNode) SetToBlank() {
	n.Node = nil
}

func (n *OptionalNode) setNodeHash(suite CipherSuite, input interface{}) error {
	data, err := syntax.Marshal(input)
	if err != nil {
		return err
	}

	n.Hash = suite.Digest(data)
	return nil
}

type LeafNodeHashInput struct {
	LeafIndex  LeafIndex
	KeyPackage *KeyPackage `tls:"optional"`
}

func (n *OptionalNode) SetLeafNodeHash(suite CipherSuite, index LeafIndex) error {
	input := LeafNodeHashInput{
		LeafIndex:  index,
		KeyPackage: nil,
	}

	if !n.Blank() {
		if n.Node.Type() != NodeTypeLeaf {
			return fmt.Errorf("mls.rtn: SetLeafNodeHash on non-leaf node")
		}

		input.KeyPackage = n.Node.Leaf
	}

	return n.setNodeHash(suite, input)
}

type ParentNodeHashInput struct {
	NodeIndex  NodeIndex
	ParentNode *ParentNode `tls:"optional"`
	LeftHash   []byte      `tls:"head=1"`
	RightHash  []byte      `tls:"head=1"`
}

func (n *OptionalNode) SetParentNodeHash(suite CipherSuite, index NodeIndex, left, right []byte) error {
	input := ParentNodeHashInput{
		NodeIndex:  index,
		ParentNode: nil,
		LeftHash:   left,
		RightHash:  right,
	}

	if !n.Blank() {
		if n.Node.Type() != NodeTypeParent {
			return fmt.Errorf("mls.rtn: SetParentNodeHash on non-leaf node")
		}

		input.ParentNode = n.Node.Parent
	}

	return n.setNodeHash(suite, input)
}

///
/// DirectPath
///
type DirectPathNode struct {
	PublicKey            HPKEPublicKey
	EncryptedPathSecrets []HPKECiphertext `tls:"head=4"`
}

type DirectPath struct {
	LeafKeyPackage KeyPackage
	Steps          []DirectPathNode `tls:"head=4"`
}

// This produces a list of parent hashes that are off by one with respect to the
// steps in the path.  The path hash at position i goes with the public key at
// position i-1, and the path hash at position 0 goes in the leaf.
func (path DirectPath) ParentHashes(suite CipherSuite) ([][]byte, error) {
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

func (path DirectPath) ParentHashValid(suite CipherSuite) error {
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

func (path *DirectPath) Sign(suite CipherSuite, initPub HPKEPublicKey, sigPriv SignaturePrivateKey, opts *KeyPackageOpts) error {
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
	if pathSecret != nil {
		priv.setPathSecrets(intersect, size, pathSecret)
	}
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

// TODO(RLB) Onece the spec is updated to have EncryptedPathSecrets as a map,
// change the TreeKEMPublicKey argument to just be a size.
func (priv *TreeKEMPrivateKey) Decap(from LeafIndex, pub TreeKEMPublicKey, context []byte, path DirectPath) error {
	// Decrypt a path secret
	ni := toNodeIndex(priv.Index)
	dp := dirpath(toNodeIndex(from), pub.Size())
	if len(dp) != len(path.Steps) {
		return fmt.Errorf("Malformed DirectPath %d %d", len(dp), len(path.Steps))
	}

	dpIndex := -1
	last := toNodeIndex(from)
	var overlap, copath NodeIndex
	for i, n := range dp {
		if inPath(ni, n) {
			dpIndex = i
			overlap = n
			copath = sibling(last, pub.Size())
			break
		}

		last = n
	}

	if dpIndex < 0 {
		return fmt.Errorf("No overlap in path")
	}

	res := pub.resolve(copath)
	if len(res) != len(path.Steps[dpIndex].EncryptedPathSecrets) {
		return fmt.Errorf("Malformed DirectPathNode %d %d", len(res), len(path.Steps[dpIndex].EncryptedPathSecrets))
	}

	var pathSecret []byte
	for i, ct := range path.Steps[dpIndex].EncryptedPathSecrets {
		n := res[i]
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
	priv.setPathSecrets(overlap, pub.Size(), pathSecret)
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

		secret := priv.PathSecrets[n][:4]
		pub := nodePriv.PublicKey.Data[:4]
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

func (pub TreeKEMPublicKey) Encap(from LeafIndex, context, leafSecret []byte, leafSigPriv SignaturePrivateKey, opts *KeyPackageOpts) (*TreeKEMPrivateKey, *DirectPath, error) {
	// Generate path secrets
	priv := NewTreeKEMPrivateKey(pub.Suite, pub.Size(), from, leafSecret)

	// Package into a DirectPath
	dp := dirpath(toNodeIndex(from), pub.Size())
	path := &DirectPath{
		LeafKeyPackage: *pub.Nodes[toNodeIndex(from)].Node.Leaf,
		Steps:          make([]DirectPathNode, len(dp)),
	}
	last := toNodeIndex(from)
	for i, n := range dp {
		nodePriv, err := priv.privateKey(n)
		if err != nil {
			return nil, nil, err
		}

		path.Steps[i] = DirectPathNode{
			PublicKey:            nodePriv.PublicKey,
			EncryptedPathSecrets: []HPKECiphertext{},
		}

		pathSecret := priv.PathSecrets[n]

		copath := sibling(last, pub.Size())
		res := pub.resolve(copath)
		path.Steps[i].EncryptedPathSecrets = make([]HPKECiphertext, len(res))
		for j, nr := range res {
			nodePub := pub.Nodes[nr].Node.PublicKey()
			path.Steps[i].EncryptedPathSecrets[j], err = pub.Suite.hpke().Encrypt(nodePub, context, pathSecret)
			if err != nil {
				return nil, nil, err
			}
		}

		last = n
	}

	// Sign the DirectPath
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

func (pub *TreeKEMPublicKey) Merge(from LeafIndex, path DirectPath) error {
	ni := toNodeIndex(from)
	pub.Nodes[ni] = newLeafNode(path.LeafKeyPackage)

	dp := dirpath(ni, pub.Size())
	if len(dp) != len(path.Steps) {
		return fmt.Errorf("Malformed DirectPath %d %d", len(dp), len(path.Steps))
	}

	for i, n := range dp {
		pub.Nodes[n] = newParentNode(path.Steps[i].PublicKey)
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
	h, err := pub.getHash(root(pub.Size()))
	if err != nil {
		// XXX(RLB)
		panic(err)
	}

	return h
}

func (pub *TreeKEMPublicKey) SetHashAll() error {
	_, err := pub.getHash(root(pub.Size()))
	return err
}

func (pub *TreeKEMPublicKey) getHash(index NodeIndex) ([]byte, error) {
	if pub.Nodes[index].Hash != nil {
		return pub.Nodes[index].Hash, nil
	}

	if level(index) == 0 {
		err := pub.Nodes[index].SetLeafNodeHash(pub.Suite, toLeafIndex(index))
		return pub.Nodes[index].Hash, err
	}

	lh, err := pub.getHash(left(index))
	if err != nil {
		return nil, err
	}

	rh, err := pub.getHash(right(index, pub.Size()))
	if err != nil {
		return nil, err
	}

	err = pub.Nodes[index].SetParentNodeHash(pub.Suite, index, lh, rh)
	return pub.Nodes[index].Hash, err
}

func (pub *TreeKEMPublicKey) setHash(index NodeIndex) error {
	if level(index) == 0 {
		return pub.Nodes[index].SetLeafNodeHash(pub.Suite, toLeafIndex(index))
	}

	if pub.Nodes[index].Hash != nil {
		return nil
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

func (pub *TreeKEMPublicKey) dump(label string) {
	fmt.Printf("~~~ %s ~~~\n", label)
	fmt.Printf("&pub = %p\n", pub)

	for i, n := range pub.Nodes {
		hash := "-"
		if len(n.Hash) > 0 {
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
