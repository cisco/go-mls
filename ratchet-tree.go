package mls

import (
	"fmt"
	"reflect"

	"github.com/bifurcation/mint/syntax"
)

///
/// Tree hash inputs
type ParentNodeInfo struct {
	PublicKey      HPKEPublicKey
	UnmergedLeaves []leafIndex `tls:"head=4"`
}

type ParentNodeHashInput struct {
	HashType  uint8
	Info      *ParentNodeInfo `tls:"optional"`
	LeftHash  []byte          `tls:"head=1"`
	RightHash []byte          `tls:"head=1"`
}

type LeafNodeInfo struct {
	PublicKey  HPKEPublicKey
	Credential Credential
}

type LeafNodeHashInput struct {
	HashType uint8
	Info     *LeafNodeInfo `tls:"optional"`
}

///
/// RatchetTreeNode
///
type RatchetTreeNode struct {
	PublicKey      *HPKEPublicKey
	UnmergedLeaves []leafIndex `tls:"head=4"`
	Credential     *Credential `tls:"optional"`
}

// Compare the public aspects of two nodes
func (n RatchetTreeNode) Equals(o RatchetTreeNode) bool {
	lhsCredNil := n.Credential == nil
	rhsCredNil := o.Credential == nil
	if lhsCredNil != rhsCredNil {
		return false
	}

	if !lhsCredNil && !n.Credential.Equals(*o.Credential) {
		return false
	}

	return reflect.DeepEqual(n.PublicKey, o.PublicKey) &&
		reflect.DeepEqual(n.UnmergedLeaves, o.UnmergedLeaves)
}

func (n RatchetTreeNode) Clone() RatchetTreeNode {
	cloned := RatchetTreeNode{
		Credential:     n.Credential,
		PublicKey:      n.PublicKey,
		UnmergedLeaves: make([]leafIndex, len(n.UnmergedLeaves)),
	}
	copy(cloned.UnmergedLeaves, n.UnmergedLeaves)
	return cloned
}

func (n *RatchetTreeNode) AddUnmerged(l leafIndex) {
	n.UnmergedLeaves = append(n.UnmergedLeaves, l)
}

///
/// OptionalRatchetTreeNode
///
type OptionalRatchetNode struct {
	Node *RatchetTreeNode `tls:"optional"`
	Hash []byte           `tls:"omit"`
}

func newLeafNode(key *HPKEPublicKey, cred *Credential) OptionalRatchetNode {
	return OptionalRatchetNode{
		Node: &RatchetTreeNode{
			PublicKey:      key,
			Credential:     cred,
			UnmergedLeaves: []leafIndex{},
		},
	}
}

func (n OptionalRatchetNode) blank() bool {
	return n.Node == nil
}

// Compare node values, not hashes
func (n OptionalRatchetNode) Equals(o OptionalRatchetNode) bool {
	switch {
	case n.blank() != o.blank():
		return false

	case n.blank():
		return true

	case !n.blank():
		return n.Node.Equals(*o.Node)
	}

	return false
}

func (n OptionalRatchetNode) Clone() OptionalRatchetNode {
	cloned := OptionalRatchetNode{
		Node: nil,
		Hash: make([]byte, len(n.Hash)),
	}

	if !n.blank() {
		var node RatchetTreeNode
		node = n.Node.Clone()
		cloned.Node = &node
	}
	copy(cloned.Hash, n.Hash)
	return cloned
}

func (n *OptionalRatchetNode) setLeafHash(cs CipherSuite) {
	lhi := LeafNodeHashInput{HashType: 0}
	if n.Node != nil {
		p := n.Node.PublicKey
		c := n.Node.Credential
		if c == nil {
			panic(fmt.Errorf("mls.rtn: Leaf node not provisioned with a credential"))
		}
		lhi.Info = &LeafNodeInfo{
			PublicKey:  *p,
			Credential: *c,
		}
	}

	h, err := syntax.Marshal(lhi)
	if err != nil {
		panic(fmt.Errorf("mls.rtn: Marshal error %v", err))
	}
	n.Hash = cs.digest(h)

}

func (n *OptionalRatchetNode) setParentHash(cs CipherSuite, l, r OptionalRatchetNode) {
	phi := ParentNodeHashInput{HashType: 1}
	if n.Node != nil {
		phi.Info = &ParentNodeInfo{
			PublicKey:      *n.Node.PublicKey,
			UnmergedLeaves: n.Node.UnmergedLeaves,
		}
	}
	phi.LeftHash = l.Hash
	phi.RightHash = r.Hash
	data, err := syntax.Marshal(phi)
	if err != nil {
		panic(fmt.Errorf("mls.rtn: set hash error %v", err))
	}
	n.Hash = cs.digest(data)
}

///
/// Ratchet Tree
///
type OptionalRatchetTreeNodeList struct {
	Data []OptionalRatchetNode `tls:"head=4"`
}

type RatchetTree struct {
	Nodes       []OptionalRatchetNode `tls:"head=4"`
	CipherSuite CipherSuite           `tls:"omit"`
	Secrets     *TreeSecrets          `tls:"omit"`
}

func (t RatchetTree) MarshalTLS() ([]byte, error) {
	enc, err := syntax.Marshal(struct {
		Nodes []OptionalRatchetNode `tls:"head=4"`
	}{
		Nodes: t.Nodes,
	})
	if err != nil {
		return nil, fmt.Errorf("mls.ratchet-tree: Marshal failed: %v", err)
	}
	return enc, nil
}

func (t *RatchetTree) UnmarshalTLS(data []byte) (int, error) {
	var ortnList OptionalRatchetTreeNodeList
	read, err := syntax.Unmarshal(data, &ortnList)
	if err != nil {
		return 0, fmt.Errorf("mls.ratchet-tree: Unmarshal failed: %v", err)
	}
	t.Nodes = ortnList.Data
	t.setHashAll(t.rootIndex())
	return read, nil
}

func newRatchetTree(cs CipherSuite) *RatchetTree {
	return &RatchetTree{
		Nodes:       []OptionalRatchetNode{},
		CipherSuite: cs,
		Secrets:     NewTreeSecrets(),
	}
}

func (t RatchetTree) Dump(label string) {
	fmt.Printf("===== tree(%s) [%04x] =====\n", label, t.CipherSuite)
	fmt.Printf("===== rootHash [%04x] =====\n", t.RootHash())

	for i, n := range t.Nodes {
		if n.blank() {
			fmt.Printf("  %2d _\n", i)
		} else {
			fmt.Printf("  %2d [%x]\n", i, n.Node.PublicKey.Data)
		}
	}
}

func (t *RatchetTree) AddLeaf(index leafIndex, key *HPKEPublicKey, credential *Credential) error {
	n := toNodeIndex(index)

	if leafCount(index) == t.size() {
		if len(t.Nodes) == 0 {
			t.Nodes = append(t.Nodes, OptionalRatchetNode{})
		} else {
			nw := int(n + 1)
			for i := len(t.Nodes); i < nw; i++ {
				t.Nodes = append(t.Nodes, OptionalRatchetNode{})
			}
		}
	}

	t.Nodes[n] = newLeafNode(key, credential)

	// update unmerged list
	dp := dirpath(n, t.size())
	for _, v := range dp {
		if v == toNodeIndex(index) || t.Nodes[v].Node == nil {
			continue
		}
		t.Nodes[v].Node.AddUnmerged(index)
	}
	t.setHashPath(index)
	return nil
}

func (t *RatchetTree) PathSecrets(start nodeIndex, pathSecret []byte) map[nodeIndex][]byte {
	secrets := map[nodeIndex][]byte{}

	curr := start
	next := parent(curr, t.size())
	secrets[curr] = make([]byte, len(pathSecret))
	copy(secrets[curr], pathSecret)

	for curr != t.rootIndex() {
		secrets[next] = t.pathStep(secrets[curr])
		curr = next
		next = parent(curr, t.size())
	}

	return secrets
}

func (t *RatchetTree) Encap(from leafIndex, context, leafSecret []byte) (*DirectPath, []byte) {
	// list of updated nodes - output
	dp := &DirectPath{}

	// update the current leaf with the new leafSecret
	leafNode := toNodeIndex(from)
	priv, err := t.nodePrivateKey(leafSecret)
	if err != nil {
		panic(err)
	}
	t.setPrivate(leafNode, priv)

	// add the leaf node's public state to the list of updates
	dp.addNode(DirectPathNode{
		t.getPublic(leafNode),
		[]HPKECiphertext{},
	})

	// generate the necessary path secrets
	secrets := t.PathSecrets(toNodeIndex(from), leafSecret)

	cp := copath(leafNode, t.size())
	for _, v := range cp {
		parent := parent(v, t.size())
		if parent == leafNode {
			continue
		}

		// update the parent with the newly computed path-secret
		pathSecret := secrets[parent]
		priv, err := t.nodePrivateKey(pathSecret)
		if err != nil {
			panic(err)
		}
		t.ensureInit(parent)
		t.setPrivate(parent, priv)

		//update nodes on the direct path to share it with others
		pathNode := DirectPathNode{PublicKey: t.getPublic(parent)}

		// encrypt the secret to resolution maintained
		res := t.resolve(v)
		for _, rnode := range res {
			pk := t.getPublic(rnode)
			ct, err := t.CipherSuite.hpke().Encrypt(pk, context, pathSecret)
			if err != nil {
				panic(fmt.Errorf("mls.rtn. Encap encrypt for resolve failed %v", err))
			}
			pathNode.EncryptedPathSecrets = append(pathNode.EncryptedPathSecrets, ct)
		}

		dp.Nodes = append(dp.Nodes, pathNode)
	}

	t.setHashPath(from)
	return dp, secrets[t.rootIndex()]
}

func (t *RatchetTree) ImplantFrom(from, to leafIndex, pathSecret []byte) ([]byte, error) {
	return t.Implant(ancestor(from, to), pathSecret)
}

func (t *RatchetTree) Implant(start nodeIndex, pathSecret []byte) ([]byte, error) {
	secrets := t.PathSecrets(start, pathSecret)

	for curr, secret := range secrets {
		priv, err := t.nodePrivateKey(secret)
		if err != nil {
			return nil, err
		}

		if t.Nodes[curr].blank() {
			return nil, fmt.Errorf("Attempt to implant blank node %v", curr)
		}

		existing := t.getPublic(curr)
		if !existing.equals(&priv.PublicKey) {
			return nil, fmt.Errorf("Incorrect secret for existing public key")
		}

		t.ensureInit(curr)
		t.setPrivate(curr, priv)
	}

	// XXX(rlb): Set root secret?
	return secrets[t.rootIndex()], nil
}

func (t *RatchetTree) decryptPathSecret(from leafIndex, context []byte, path *DirectPath) (nodeIndex, []byte, error) {
	cp := copath(toNodeIndex(from), t.size())
	if len(path.Nodes) != len(cp)+1 {
		return 0, nil, fmt.Errorf("mls.rtn: Malformed (cp) DirectPath %d %d %v", len(path.Nodes), len(cp)+1, cp)
	}

	if len(path.Nodes[0].EncryptedPathSecrets) != 0 {
		return 0, nil, fmt.Errorf("mls.rtn: Malformed initial DirectPath node")
	}

	for i, curr := range cp {
		res := t.resolve(curr)
		pathNode := path.Nodes[i+1]

		if len(pathNode.EncryptedPathSecrets) != len(res) {
			return 0, nil, fmt.Errorf("mls.rtn: Malformed Ratchet Node")
		}

		for idx, v := range res {
			if !t.hasPrivate(v) {
				continue
			}

			encryptedSecret := pathNode.EncryptedPathSecrets[idx]
			priv := t.getPrivate(v)
			pathSecret, err := t.CipherSuite.hpke().Decrypt(priv, context, encryptedSecret)
			if err != nil {
				return 0, nil, fmt.Errorf("mls:rtn: Ratchet node %v Decryption failure %v", v, err)
			}

			parentNode := parent(curr, t.size())
			return parentNode, pathSecret, nil
		}
	}

	return 0, nil, fmt.Errorf("mls:rtn: No private key available for decrypt")
}

func (t *RatchetTree) Decap(from leafIndex, context []byte, path *DirectPath) ([]byte, error) {
	// Set public keys
	dp := dirpath(toNodeIndex(from), t.size())
	if len(path.Nodes) != len(dp) {
		return nil, fmt.Errorf("mls.rtn: Malformed (dp) DirectPath %d %d", len(path.Nodes), len(dp)+1)
	}

	for i, node := range dp {
		t.ensureInit(node)
		t.setPublic(node, path.Nodes[i].PublicKey)
	}

	// Decrypt and implant path secret
	overlap, pathSecret, err := t.decryptPathSecret(from, context, path)
	if err != nil {
		return nil, err
	}

	rootSecret, err := t.Implant(overlap, pathSecret)
	if err != nil {
		return nil, err
	}

	t.setHashPath(from)
	return rootSecret, nil
}

func (t *RatchetTree) Merge(index leafIndex, secret []byte) error {
	curr := toNodeIndex(index)
	if t.Nodes[curr].blank() {
		return fmt.Errorf("mls.rtn.Merge: Cannot update a blank leaf")
	}

	priv, err := t.CipherSuite.hpke().Derive(secret)
	if err != nil {
		return err
	}

	t.setPrivate(curr, priv)
	t.setHashPath(index)
	return nil
}

func (t *RatchetTree) MergePublic(index leafIndex, key *HPKEPublicKey) error {
	curr := toNodeIndex(index)
	if t.Nodes[curr].blank() {
		return fmt.Errorf("mls.rtn.MergePK: Cannot update a blank leaf")
	}

	t.setPublic(curr, *key)
	t.setHashPath(index)
	return nil
}

func (t *RatchetTree) MergePrivate(index leafIndex, key *HPKEPrivateKey) error {
	curr := toNodeIndex(index)
	if t.Nodes[curr].blank() {
		return fmt.Errorf("mls.rtn.MergePK: Cannot update a blank leaf")
	}

	t.setPrivate(curr, *key)
	t.setHashPath(index)
	return nil
}

func (t *RatchetTree) BlankPath(index leafIndex, includeLeaf bool) error {
	if len(t.Nodes) == 0 {
		return nil
	}

	lc := t.size()
	r := t.rootIndex()
	first := true

	curr := toNodeIndex(index)

	for {
		if curr == r {
			break
		}
		skip := first && !includeLeaf
		if !skip {
			t.Nodes[curr].Node = nil
		}
		curr = parent(curr, lc)
	}

	t.Nodes[r].Node = nil
	t.setHashPath(index)
	return nil
}

func (t *RatchetTree) GetCredential(index leafIndex) *Credential {
	ni := toNodeIndex(index)
	if t.Nodes[ni].Node == nil {
		panic(fmt.Errorf("mls:rtn: requested credential for a blank leaf"))
	}
	c := t.Nodes[ni].Node.Credential
	if c == nil {
		panic(fmt.Errorf("mls:rtn: Leaf node was not populated with a credential"))
	}
	return c
}

func (t *RatchetTree) RootHash() []byte {
	r := root(t.size())
	return t.Nodes[r].Hash
}

func (t *RatchetTree) Equals(o *RatchetTree) bool {
	if len(t.Nodes) != len(o.Nodes) {
		return false
	}

	for i := 0; i < int(t.size()); i++ {
		if !t.Nodes[i].Equals(o.Nodes[i]) {
			return false
		}
	}
	return true
}

func (t *RatchetTree) LeftmostFree() leafIndex {
	curr := leafIndex(0)
	for {
		if t.occupied(curr) && curr < leafIndex(t.size()) {
			curr++
		} else {
			break
		}
	}
	return curr
}

func (t *RatchetTree) Find(cik ClientInitKey) (leafIndex, bool) {
	num := t.size()
	for i := leafIndex(0); leafCount(i) < num; i++ {
		idx := toNodeIndex(i)
		n := t.Nodes[idx]
		if n.blank() {
			continue
		}
		hpkeMatch := cik.InitKey.equals(n.Node.PublicKey)
		credMatch := cik.Credential.Equals(*n.Node.Credential)
		if hpkeMatch && credMatch {
			return i, true
		}
	}

	return 0, false
}

//// Ratchet Tree helpers functions

// number of leaves in the ratchet tree
func (t *RatchetTree) size() leafCount {
	return leafWidth(nodeCount(len(t.Nodes)))
}

func (t *RatchetTree) nodeSize() nodeCount {
	return nodeCount(len(t.Nodes))
}

func (t *RatchetTree) occupied(l leafIndex) bool {
	n := toNodeIndex(l)
	if int(n) >= len(t.Nodes) {
		return false
	}
	return !t.Nodes[n].blank()
}

// Node accessors
func (t *RatchetTree) setPublic(n nodeIndex, pub HPKEPublicKey) {
	t.Nodes[n].Node.PublicKey = &pub
	t.Nodes[n].Node.UnmergedLeaves = []leafIndex{}
}

func (t *RatchetTree) getPublic(n nodeIndex) HPKEPublicKey {
	return *t.Nodes[n].Node.PublicKey
}

func (t *RatchetTree) setPrivate(n nodeIndex, priv HPKEPrivateKey) {
	t.Secrets.PrivateKeys[n] = priv
	t.setPublic(n, priv.PublicKey)
}

func (t *RatchetTree) getPrivate(n nodeIndex) HPKEPrivateKey {
	return t.Secrets.PrivateKeys[n]
}

func (t *RatchetTree) hasPrivate(n nodeIndex) bool {
	_, ok := t.Secrets.PrivateKeys[n]
	return ok
}

func (t *RatchetTree) ensureInit(n nodeIndex) {
	if t.Nodes[n].Node == nil {
		t.Nodes[n].Node = &RatchetTreeNode{UnmergedLeaves: []leafIndex{}}
	}
}

func (t *RatchetTree) rootIndex() nodeIndex {
	return root(t.size())
}

func (t *RatchetTree) nodeStep(pathSecret []byte) []byte {
	return t.CipherSuite.hkdfExpandLabel(pathSecret, "node", []byte{}, t.CipherSuite.constants().SecretSize)
}

func (t *RatchetTree) pathStep(pathSecret []byte) []byte {
	ps := t.CipherSuite.hkdfExpandLabel(pathSecret, "path", []byte{}, t.CipherSuite.constants().SecretSize)
	return ps
}

func (t *RatchetTree) nodePrivateKey(pathSecret []byte) (HPKEPrivateKey, error) {
	ns := t.nodeStep(pathSecret)
	return t.CipherSuite.hpke().Derive(ns)
}

func (t *RatchetTree) resolve(index nodeIndex) []nodeIndex {
	// Resolution of non-blank is node + unmerged leaves
	if t.Nodes[index].Node != nil {
		res := []nodeIndex{index}
		for _, v := range t.Nodes[index].Node.UnmergedLeaves {
			res = append(res, nodeIndex(v))
		}
		return res
	}

	// Resolution of blank leaf is the empty list
	if level(index) == 0 {
		return []nodeIndex{}
	}

	// Resolution of blank intermediate node is concatenation of the resolutions
	// of the children
	l := t.resolve(left(index))
	r := t.resolve(right(index, t.size()))
	l = append(l, r...)
	return l
}

func (t *RatchetTree) setHash(index nodeIndex) {
	if level(index) == 0 {
		t.Nodes[index].setLeafHash(t.CipherSuite)
		return
	}
	l := left(index)
	r := right(index, t.size())
	t.Nodes[index].setParentHash(t.CipherSuite, t.Nodes[l], t.Nodes[r])
}

func (t *RatchetTree) setHashPath(index leafIndex) {
	curr := toNodeIndex(index)
	t.Nodes[curr].setLeafHash(t.CipherSuite)

	size := t.size()
	r := root(size)
	for {
		if curr == r {
			break
		}
		curr = parent(curr, size)
		l := left(curr)
		r := right(curr, size)
		t.Nodes[curr].setParentHash(t.CipherSuite, t.Nodes[l], t.Nodes[r])
	}
}

func (t *RatchetTree) setHashAll(index nodeIndex) {
	if len(t.Nodes) == 0 {
		return
	}

	if level(index) == 0 {
		t.setHash(index)
		return
	}

	l := left(index)
	r := right(index, t.size())
	t.setHashAll(l)
	t.setHashAll(r)
	t.setHash(index)
}

func (t RatchetTree) clone() *RatchetTree {
	var n []OptionalRatchetNode
	for _, node := range t.Nodes {
		n = append(n, node.Clone())
	}

	cloned := &RatchetTree{
		Nodes:       n,
		CipherSuite: t.CipherSuite,
		Secrets:     t.Secrets.Clone(),
	}
	return cloned
}
