package mls

import (
	"fmt"
	"reflect"

	"github.com/bifurcation/mint/syntax"
)

//// Tree Hashes
type ParentNodeInfo struct {
	PublicKey      *HPKEPublicKey
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

//// ratchet tree node and helpers

//// RatchetTree Node
type RatchetTreeNode struct {
	Cred           *Credential `tls:"optional"`
	PublicKey      *HPKEPublicKey
	PrivateKey     *HPKEPrivateKey
	UnmergedLeaves []leafIndex `tls:"head=2"`
	CipherSuite    CipherSuite
}

func newRatchetTreeNode(cs CipherSuite, secret []byte) *RatchetTreeNode {
	if len(secret) > 0 {
		priv, err := cs.hpke().Derive(secret)
		if err != nil {
			panic(fmt.Errorf("hpke private key generation failed: %v", err))
		}

		return &RatchetTreeNode{
			Cred:           nil,
			PrivateKey:     &priv,
			PublicKey:      &priv.PublicKey,
			UnmergedLeaves: []leafIndex{},
			CipherSuite:    cs,
		}
	}

	return &RatchetTreeNode{
		Cred:           nil,
		PrivateKey:     nil,
		PublicKey:      nil,
		UnmergedLeaves: []leafIndex{},
		CipherSuite:    cs,
	}
}

// Compare the public aspects of two nodes
func (n RatchetTreeNode) Equals(o RatchetTreeNode) bool {
	lhsCredNil := (n.Cred == nil)
	rhsCredNil := (o.Cred == nil)
	if lhsCredNil != rhsCredNil {
		return false
	}
	if !lhsCredNil && !reflect.DeepEqual(n.Cred, o.Cred) {
		return false
	}

	if !reflect.DeepEqual(n.PublicKey, o.PublicKey) ||
		!reflect.DeepEqual(n.UnmergedLeaves, o.UnmergedLeaves) ||
		!reflect.DeepEqual(n.CipherSuite, o.CipherSuite) {
		return false
	}

	return true
}

func (n *RatchetTreeNode) Merge(o *RatchetTreeNode) {
	if o.PublicKey != nil && !o.PublicKey.equals(n.PublicKey) {
		n.PublicKey = o.PublicKey
		n.PrivateKey = nil
	}

	if o.PrivateKey != nil {
		n.PrivateKey = o.PrivateKey
	}

	// reset unmerged leaves since the node is being updated.
	n.UnmergedLeaves = []leafIndex{}
}

func (n *RatchetTreeNode) AddUnmerged(l leafIndex) {
	n.UnmergedLeaves = append(n.UnmergedLeaves, l)
}

type OptionalRatchetNode struct {
	Node *RatchetTreeNode `tls:"optional"`
	hash []byte           `tls:"omit"`
}

func (n OptionalRatchetNode) blank() bool {
	return n.Node == nil
}

// Compare node values, not hashes
func (n OptionalRatchetNode) Equals(o OptionalRatchetNode) bool {
	lhsBlank := n.Node == nil
	rhsBlank := o.Node == nil
	if lhsBlank != rhsBlank {
		return false
	}

	if !lhsBlank && !n.Node.Equals(*o.Node) {
		return false
	}

	return true
}

func (n *OptionalRatchetNode) setLeafHash(cs CipherSuite) {
	lhi := LeafNodeHashInput{HashType: 0}
	if n.Node != nil {
		p := n.Node.PublicKey
		c := n.Node.Cred
		if c == nil {
			panic(fmt.Errorf("mls.rtn: Leaf node not provisioned with a credentialp"))
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
	n.hash = cs.digest(h)

}

func (n *OptionalRatchetNode) merge(o *RatchetTreeNode) {
	if n.Node == nil {
		n.Node = o
	} else {
		n.Node.Merge(o)
	}
}

func (n *OptionalRatchetNode) setHash(cs CipherSuite, l, r OptionalRatchetNode) {
	phi := ParentNodeHashInput{HashType: 1}
	if n.Node != nil {
		phi.Info = &ParentNodeInfo{PublicKey: n.Node.PublicKey, UnmergedLeaves: n.Node.UnmergedLeaves}
	}
	phi.LeftHash = l.hash
	phi.RightHash = r.hash
	data, err := syntax.Marshal(phi)
	if err != nil {
		panic(fmt.Errorf("mls.rtn: set hash error %v", err))
	}
	n.hash = cs.digest(data)
}

func (n *OptionalRatchetNode) hasPrivate() bool {
	if n.Node != nil && n.Node.PrivateKey != nil {
		return true
	}
	return false
}

//// Ratchet Tree
type RatchetTree struct {
	Nodes       []OptionalRatchetNode `tls:"head=2"`
	CipherSuite CipherSuite
	NumLeaves   leafCount
}

func newRatchetTree(cs CipherSuite) *RatchetTree {
	return &RatchetTree{
		Nodes:       []OptionalRatchetNode{},
		CipherSuite: cs,
	}
}

func (t RatchetTree) Dump(label string) {
	fmt.Printf("===== tree(%s) [%d] [%04x] =====\n", label, t.NumLeaves, t.CipherSuite)
	for i, n := range t.Nodes {
		if n.blank() {
			fmt.Printf("  %2d _\n", i)
		} else {
			fmt.Printf("  %2d [%x]\n", i, n.Node.PublicKey.Data)
		}
	}
}

func (t *RatchetTree) AddLeaf(index leafIndex, key *HPKEPublicKey, credential *Credential) {
	n := toNodeIndex(index)
	sz := uint32(t.size())
	if uint32(index) == sz {
		if len(t.Nodes) == 0 {
			t.Nodes = append(t.Nodes, OptionalRatchetNode{})
		} else {
			nw := int(n + 1)
			for i := len(t.Nodes); i < nw; i++ {
				t.Nodes = append(t.Nodes, OptionalRatchetNode{})
			}
		}
	}

	if t.Nodes[n].Node != nil {
		panic(fmt.Errorf("mls.rtn:addLeaf: aff target already occupied"))
	}

	node := &RatchetTreeNode{
		PublicKey:      key,
		Cred:           credential,
		UnmergedLeaves: []leafIndex{},
	}

	t.Nodes[n].Node = node
	t.NumLeaves += 1

	// update unmerged list
	dp := dirpath(n, t.NumLeaves)
	for _, v := range dp {
		if v == toNodeIndex(index) || t.Nodes[v].Node == nil {
			continue
		}
		t.Nodes[v].Node.AddUnmerged(index)
	}
	t.setHashPath(index)
}

func (t *RatchetTree) Encap(from leafIndex, context, leafSecret []byte) (*DirectPath, []byte) {
	// list of updated nodes - output
	dp := &DirectPath{}

	// update the current leaf with the new leafSecret
	leafNode := toNodeIndex(from)
	n := t.newNode(leafSecret)
	t.Nodes[leafNode].Node.Merge(n)

	// add the leaf node's public state to the list of updates
	dp.addNode(DirectPathNode{
		*t.Nodes[leafNode].Node.PublicKey,
		[]HPKECiphertext{}})

	pathSecret := leafSecret
	cp := copath(leafNode, t.size())
	for _, v := range cp {
		pathSecret = t.pathStep(pathSecret)
		parent := parent(v, t.size())
		if parent == leafNode {
			continue
		}

		// update the non-updated child's parent with the newly
		// computed path-secret
		n = t.newNode(pathSecret)
		t.Nodes[parent].Node = n

		//update nodes on the direct path to share it with others
		pathNode := DirectPathNode{PublicKey: *t.Nodes[parent].Node.PublicKey}

		// encrypt the secret to resolution maintained
		res := t.resolve(v)
		for _, rnode := range res {
			pk := t.Nodes[rnode].Node.PublicKey
			ct, err := t.CipherSuite.hpke().Encrypt(*pk, []byte{}, pathSecret)
			if err != nil {
				panic(fmt.Errorf("mls.rtn. Encap encrypt for resolve failed %v", err))
			}
			pathNode.EncryptedPathSecrets = append(pathNode.EncryptedPathSecrets, ct)
		}

		dp.Nodes = append(dp.Nodes, pathNode)
	}

	t.setHashPath(from)

	return dp, pathSecret
}

func (t *RatchetTree) Decap(from leafIndex, context []byte, path *DirectPath) []byte {
	cp := copath(toNodeIndex(from), t.size())
	if len(path.Nodes) != len(cp)+1 {
		panic(fmt.Errorf("mls.rtn:Decap Malformed Directpath"))
	}

	dp := dirpath(toNodeIndex(from), t.size())

	// leaf
	if len(path.Nodes[0].EncryptedPathSecrets) != 0 {
		panic(fmt.Errorf("mls.rtn:Decap Malformed leaf node"))
	}

	leafNode := toNodeIndex(from)
	t.Nodes[leafNode].merge(&RatchetTreeNode{PublicKey: &path.Nodes[0].PublicKey})

	// handle rest of the path now
	var pathSecret []byte
	var err error
	haveSecret := false
	for i := 0; i < len(cp); i++ {
		curr := cp[i]
		pathNode := path.Nodes[i+1]
		if !haveSecret {
			res := t.resolve(curr)
			if len(pathNode.EncryptedPathSecrets) != len(res) {
				panic(fmt.Errorf("mls.rtn: Malformed Ratchet Node"))
			}
			for idx, v := range res {
				if !t.Nodes[v].hasPrivate() {
					continue
				}
				encryptedSecret := pathNode.EncryptedPathSecrets[idx]
				priv := t.Nodes[v].Node.PrivateKey
				pathSecret, err = t.CipherSuite.hpke().Decrypt(*priv, []byte{}, encryptedSecret)
				if err != nil {
					panic(fmt.Errorf("mls:rtn: Ratchet node %v Decryption failure %v", v, err))
				}
				haveSecret = true
			}
		} else {
			pathSecret = t.pathStep(pathSecret)
		}

		if haveSecret {
			temp := t.newNode(pathSecret)
			if !temp.PublicKey.equals(&pathNode.PublicKey) {
				panic(fmt.Errorf("mls:rtn: incorrect public key"))
			}
			t.Nodes[dp[i+1]].merge(temp)
		} else {
			t.Nodes[dp[i+1]].merge(&RatchetTreeNode{
				PublicKey:      &pathNode.PublicKey,
				UnmergedLeaves: []leafIndex{},
			})
		}
	}
	t.setHashPath(from)
	return pathSecret
}

func (t *RatchetTree) Merge(index leafIndex, key interface{}) {
	curr := toNodeIndex(index)
	if t.Nodes[curr].Node == nil {
		panic(fmt.Errorf("mls.rtn.Merge: Cannot update a blank leaf"))
	}
	switch v := key.(type) {
	case HPKEPublicKey:
		t.Nodes[curr].Node.Merge(&RatchetTreeNode{PublicKey: &v})
	case HPKEPrivateKey:
		t.Nodes[curr].Node.Merge(&RatchetTreeNode{PrivateKey: &v})
	case []byte:
		t.Nodes[curr].Node.Merge(newRatchetTreeNode(t.CipherSuite, v))
	default:
		panic(fmt.Errorf("mls.rtn: Merge unsupported type %T", v))
	}
}

func (t *RatchetTree) BlankPath(index leafIndex, includeLeaf bool) {
	if len(t.Nodes) == 0 {
		return
	}

	nc := t.nodeSize()
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
		curr = parent(curr, leafCount(nc))
	}

	t.Nodes[r].Node = nil
	t.setHashPath(index)
}

func (t *RatchetTree) GetCredential(index leafIndex) *Credential {
	ni := toNodeIndex(index)
	if t.Nodes[ni].Node == nil {
		panic(fmt.Errorf("mls:rtn: requested credential for a blank leaf"))
	}
	c := t.Nodes[ni].Node.Cred
	if c == nil {
		panic(fmt.Errorf("mls:rtn: Leaf node was not populated with a credential"))
	}
	return c
}

func (t *RatchetTree) RootHash() []byte {
	r := root(t.size())
	return t.Nodes[r].hash
}

func (t *RatchetTree) Equals(o *RatchetTree) bool {
	if t.NumLeaves != o.NumLeaves {
		return false
	}

	for i := 0; i < int(t.size()); i++ {
		if !t.Nodes[i].Equals(o.Nodes[i]) {
			return false
		}
	}
	return true
}

func (t *RatchetTree) LeftMostFree() leafIndex {
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
	for i := leafIndex(0); leafCount(i) < t.size(); i++ {
		n := t.Nodes[toNodeIndex(i)]
		if n.Node != nil || n.Node.Cred == nil {
			continue
		}
		hpkeMatch := cik.InitKey.equals(n.Node.PublicKey)
		credMatch := cik.Credential == *n.Node.Cred
		if hpkeMatch && credMatch {
			return i, true
		}
	}
	// 0 is a bad idea , use some Max value here ?
	// calling code must check for bool before using the index,
	// so it might be ok
	// ask richard...
	return 0, false
}

//// Ratchet Tree helpers functions

// number of leaves in the ratchet tree
func (t *RatchetTree) size() leafCount {
	return t.NumLeaves
}

func (t *RatchetTree) occupied(l leafIndex) bool {
	n := nodeIndex(l)
	if nodeCount(n) >= t.nodeSize() {
		return false
	}
	return true
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

func (t *RatchetTree) newNode(pathSecret []byte) *RatchetTreeNode {
	ns := t.nodeStep(pathSecret)
	return newRatchetTreeNode(t.CipherSuite, ns)
}

func (t *RatchetTree) nodeSize() nodeCount {
	if t.NumLeaves == 0 {
		return 0
	}
	return nodeWidth(t.NumLeaves)
}

func (t *RatchetTree) resolve(index nodeIndex) []nodeIndex {
	res := []nodeIndex{index}
	if t.Nodes[index].Node != nil {
		for _, v := range t.Nodes[index].Node.UnmergedLeaves {
			res = append(res, nodeIndex(v))
		}
		return res
	}

	// leaf - empty resolution
	if level(index) == 0 {
		return []nodeIndex{}
	}

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
	t.Nodes[index].setHash(t.CipherSuite, t.Nodes[l], t.Nodes[r])
}

func (t *RatchetTree) setHashPath(index leafIndex) {
	curr := toNodeIndex(index)
	t.setHash(curr)
	r := root(t.size())
	for {
		if curr == r {
			break
		}
		curr = parent(curr, t.size())
		t.setHash(curr)
	}
}
