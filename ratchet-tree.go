package mls

import (
	"encoding/hex"
	"fmt"
	"github.com/bifurcation/mint/syntax"
)


//// Tree Hashes
type ParentNodeInfo struct {
	PublicKey      *HPKEPublicKey
	UnmergedLeaves []leafIndex     `tls:"head=4"`
}

type ParentNodeHashInput struct {
	HashType  uint8
	Info      *ParentNodeInfo  `tls:"optional"`
	LeftHash  []byte           `tls:"head=1"`
	RightHash []byte           `tls:"head=1"`
}


type LeafNodeInfo struct {
	PublicKey  HPKEPublicKey
	Credential Credential
}

type LeafNodeHashInput struct {
	HashType  uint8
	Info      *LeafNodeInfo  `tls:"optional"`
}

type OptionalRatchetNode struct {
	node *RatchetTreeNode
	hash []byte
}

func (n *OptionalRatchetNode) setLeafHash(cs CipherSuite) {
	lhi := LeafNodeHashInput{HashType: 0}
	if n.node != nil {
		p := n.node.PublicKey
		c := n.node.Cred
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
	fmt.Printf("lhi-input : %v\n", hex.EncodeToString(h))
	n.hash = cs.digest(h)
	fmt.Printf("lhi-digest-out : %v\n", hex.EncodeToString(n.hash))

}

func (n *OptionalRatchetNode) merge(o *RatchetTreeNode) {
	if n.node == nil{
		n.node = o
	} else {
		n.node.Merge(o)
	}
}

func(n *OptionalRatchetNode) setHash(cs CipherSuite, l OptionalRatchetNode, r OptionalRatchetNode) {
	phi := ParentNodeHashInput{ HashType: 1}
	if n.node != nil {
		phi.Info = &ParentNodeInfo{PublicKey: n.node.PublicKey, UnmergedLeaves: n.node.UnmergedLeaves}
	}
	phi.LeftHash = l.hash
	phi.RightHash = r.hash
	//fmt.Printf("phi:l-Hash %v\n", hex.EncodeToString(phi.LeftHash))
	//fmt.Printf("phi:r-Hash %v\n", hex.EncodeToString(phi.RightHash))

	data, err := syntax.Marshal(phi)
	//fmt.Printf("phi: Marhsal (Digest-in) %v\n", hex.EncodeToString(data))

	if err != nil {
		panic(fmt.Errorf("mls.rtn: set hash error %v", err))
	}
	n.hash = cs.digest(data)
	//fmt.Printf("phi: Digest Output %v\n", hex.EncodeToString(n.hash))

}

func (n *OptionalRatchetNode) hasPrivate() bool {
	if n.node != nil && n.node.PrivateKey != nil {
		return true
	}
	return false
}

//// RatchetTree Node
type RatchetTreeNode struct {
	Cred            *Credential     // populated iff this node is a leaf
	PublicKey       *HPKEPublicKey
	PrivateKey      *HPKEPrivateKey
	UnmergedLeaves  []leafIndex
	CipherSuite     CipherSuite

}

func newRatchetTreeNode(cs CipherSuite, secret []byte) *RatchetTreeNode {
	if len(secret) > 0 {
		priv, err := cs.hpke().Derive(secret)
		if err != nil {
			panic(fmt.Errorf("hpke private key generation failed: %v", err))
		}

		return &RatchetTreeNode {
			Cred: nil,
			PrivateKey: &priv,
			PublicKey: &priv.PublicKey,
			UnmergedLeaves: []leafIndex{},
			CipherSuite: cs,
		}
	}


	return &RatchetTreeNode{
		Cred: nil,
		PrivateKey: nil,
		PublicKey: nil,
		UnmergedLeaves: []leafIndex{},
		CipherSuite: cs,
	}
}

func (n *RatchetTreeNode) Merge(o *RatchetTreeNode) {
	fmt.Printf("other pk %v\n", hex.EncodeToString(o.PublicKey.Data))
	fmt.Printf("mine pk %v\n", hex.EncodeToString(n.PublicKey.Data))

	if o.PublicKey != nil && !o.PublicKey.equals(n.PublicKey) {
		n.PublicKey = o.PublicKey
		n.PrivateKey = nil
	}

	fmt.Printf("other pk %v\n", hex.EncodeToString(o.PublicKey.Data))
	fmt.Printf("mine pk %v\n", hex.EncodeToString(n.PublicKey.Data))


	if o.PrivateKey != nil {
		n.PrivateKey = o.PrivateKey
	}

	// reset unmerged leaves since the node is being updated.
	n.UnmergedLeaves = []leafIndex{}
}

func (n *RatchetTreeNode) AddUnmerged(l leafIndex) {
	n.UnmergedLeaves = append(n.UnmergedLeaves, l)
}



//// Ratchet Tree
type RatchetTree struct {
	nodes     []OptionalRatchetNode
	cs        CipherSuite
	numLeaves leafCount
}

func newRatchetTree(cs CipherSuite) *RatchetTree {
	return &RatchetTree{
		nodes: []OptionalRatchetNode{},
		cs: cs,
	}
}

func (t *RatchetTree) Encap(from leafIndex, context, leafSecret []byte) (*DirectPath, []byte) {
	dp := &DirectPath{}
	leafNode := toNodeIndex(from)
	n := t.newNode(leafSecret)
	fmt.Printf("encap-1.1: leaf public key %v\n", hex.EncodeToString(n.PublicKey.Data))
	if t.nodes[leafNode].node != nil {
		t.nodes[leafNode].node.Merge(n)
		fmt.Printf("encap-1.2: leaf public key %v\n", hex.EncodeToString(t.nodes[leafNode].node.PublicKey.Data))
		dp.addNode(RatchetNode{*t.nodes[leafNode].node.PublicKey, []HPKECiphertext{}})
	} else {
		// replace blank node
		t.nodes[leafNode].node = n
	}

	pathSecret := leafSecret
	cp := copath(leafNode, t.size())
	fmt.Printf("copath for [%v]: [%v]\n", leafNode, cp)
	for _, v := range cp {
		pathSecret = t.pathStep(pathSecret)
		parent := parent(v, t.size())
		if parent == leafNode {
			fmt.Println("PARENT SAME AS LEAF")
			continue
		}
		n = t.newNode(pathSecret)
		t.nodes[parent].node = n
		//update nodes on the direct path to share it with others
		pathNode := RatchetNode{PublicKey: *t.nodes[parent].node.PublicKey}

		// encrypt the secret to resolution maintained
		for _, rnode := range t.resolve(v) {
			pk := t.nodes[rnode].node.PublicKey
			ct, err := t.cs.hpke().Encrypt(*pk, []byte{}, pathSecret)
			if err != nil {
				panic(fmt.Errorf("mls.rtn. Encap encrypt for resolve failed %v", err))
			}
			pathNode.EncryptedPathSecret = append(pathNode.EncryptedPathSecret, ct)
		}

		dp.Nodes = append(dp.Nodes, pathNode)
	}

	fmt.Printf("encap-2: leaf public keyy %v\n", hex.EncodeToString(t.nodes[leafNode].node.PublicKey.Data))

	t.setHashPath(from)
	fmt.Printf("encap-3: leaf public keyy %v\n", hex.EncodeToString(t.nodes[leafNode].node.PublicKey.Data))

	return dp, pathSecret
}


func (t *RatchetTree) Decap(from leafIndex, context []byte, path DirectPath) []byte{
	cp := copath(toNodeIndex(from), t.size())
	if len(path.Nodes) != len(cp) +1 {
		panic(fmt.Errorf("mls.rtn:Decap Malforemd Directpath"))
	}

	dp := dirpath(toNodeIndex(from), t.size())
	dp = append(dp, t.rootIndex())

	// leaf
	if len(path.Nodes[0].EncryptedPathSecret) != 0 {
		panic(fmt.Errorf("mls.rtn:Decap Malformed leaf node"))
	}

	t.nodes[from].merge(&RatchetTreeNode{PublicKey: &path.Nodes[0].PublicKey})

	var pathSecret []byte
	var err error
	haveSecret := false
	for i := 0; i < len(cp); i++ {
		curr := cp[i]
		pathNode := path.Nodes[i+1]
		if !haveSecret {
			res := t.resolve(curr)
			if len(pathNode.EncryptedPathSecret) != len(res) {
				panic(fmt.Errorf("mls.rtn: Malformed Ratchet Node"))
			}
			for _, v := range res {
				if !t.nodes[v].hasPrivate() {
					continue
				}
				encryptedSecret := pathNode.EncryptedPathSecret[v]
				priv := t.nodes[v].node.PrivateKey
				pathSecret, err = t.cs.hpke().Decrypt(*priv, []byte{}, encryptedSecret)
				if err != nil {
					panic(fmt.Errorf("mls:rtn: Ratchet node %v Decryption failure %v", v, err))
				}
				haveSecret = true
			}
		} else {
			pathSecret = t.pathStep(pathSecret)
		}

		if haveSecret {
			temp := newRatchetTreeNode(t.cs, pathSecret)
			if !temp.PublicKey.equals(&pathNode.PublicKey) {
				panic(fmt.Errorf("mls:rtn: incorrect public key"))
			}
			t.nodes[dp[i+1]].merge(temp)
		} else {
			t.nodes[dp[i+1]].merge(&RatchetTreeNode{PublicKey: &pathNode.PublicKey})
		}

	}
	t.setHashPath(from)
	return pathSecret
}

func (t *RatchetTree) AddLeaf(index leafIndex, key *HPKEPublicKey, credential *Credential) {

	n := toNodeIndex(index)
	sz := uint32(t.size())
	if uint32(index) == sz {
		if len(t.nodes) == 0 {
			t.nodes = append(t.nodes, OptionalRatchetNode{})
		} else {
			nw := int(n+1)
			for i := len(t.nodes); i < nw; i++ {
				t.nodes = append(t.nodes, OptionalRatchetNode{})
			}
		}
	}

	if t.nodes[n].node != nil {
		panic(fmt.Errorf("mls.rtn:addLeaf: aff target already occupied"))
	}

	node := RatchetTreeNode{
		PublicKey: key,
		Cred: credential,
	}
	t.nodes[n].node = &node
	t.numLeaves += 1

	sz = uint32(t.size())
	// update unmerged list
	dp := dirpath(n, t.numLeaves)
	for _, v := range dp {
		if leafIndex(v) == index || t.nodes[v].node == nil {
			continue
		}
		t.nodes[v].node.AddUnmerged(index)
	}
	t.setHashPath(index)
 }

func (t *RatchetTree) Merge(index leafIndex, key interface{}) {
	curr := toNodeIndex(index)
	if t.nodes[curr].node == nil {
		panic(fmt.Errorf("mls.rtn.Merge: Cannot update a blank leaf"))
	}
	switch v := key.(type) {
	case HPKEPublicKey:
		t.nodes[curr].node.Merge(&RatchetTreeNode{PublicKey: &v})
	case HPKEPrivateKey:
		t.nodes[curr].node.Merge(&RatchetTreeNode{PrivateKey: &v})
	case []byte:
		t.nodes[curr].node.Merge(newRatchetTreeNode(t.cs, v))
	default:
		panic(fmt.Errorf("mls.rtn: Merge unsupported type %T", v))
	}
}

func (t *RatchetTree) BlankPath(index leafIndex, includeLeaf bool) {
	if len(t.nodes) == 0 {
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
			t.nodes[curr].node = nil
		}
		curr = parent(curr, leafCount(nc))
	}

	t.nodes[r].node = nil
	t.setHashPath(index)
}

func (t *RatchetTree) GetCredential(index leafIndex) *Credential {
	ni := toNodeIndex(index)
	if t.nodes[ni].node == nil {
		panic(fmt.Errorf("mls:rtn: requested credential for a blank leaf"))
	}
	c := t.nodes[ni].node.Cred
	if c == nil {
		panic(fmt.Errorf("mls:rtn: Leaf node was not populated with a credential"))
	}
	return c
}

func (t *RatchetTree) RootHash() []byte {
	r := root(t.size())
	return t.nodes[r].hash
}

func (t *RatchetTree) leftMostFree() leafIndex {
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
	for i := leafIndex(0) ; leafCount(i) < t.size(); i++ {
		n := t.nodes[toNodeIndex(i)]
		if n.node != nil || n.node.Cred == nil {
			continue
		}
		hpkeMatch := cik.InitKey.equals(n.node.PublicKey)
		credMatch := cik.Credential == *n.node.Cred
		if hpkeMatch && credMatch {
			return i, true
		}
	}
	// 0 is a bad idea , use some Max value here ?
	return 0, false
}

//// Ratchet Tree helpers

// number of leaves in the ratchet tree
func (t *RatchetTree) size() leafCount {
	return t.numLeaves
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
func (t *RatchetTree) nodeStep(pathSecret []byte) []byte{
	return t.cs.hkdfExpandLabel(pathSecret, "node", []byte{}, t.cs.constants().SecretSize)
}

func (t *RatchetTree) pathStep(pathSecret []byte) []byte{
	ps := t.cs.hkdfExpandLabel(pathSecret, "path", []byte{}, t.cs.constants().SecretSize)
	fmt.Printf("ps: %v\n", hex.EncodeToString(ps))
	return ps
}

func (t *RatchetTree) newNode(pathSecret []byte) *RatchetTreeNode {
	ns := t.nodeStep(pathSecret)
	return newRatchetTreeNode(t.cs, ns)
}

func (t *RatchetTree) nodeSize() nodeCount {
	if t.numLeaves == 0 {
		return 0
	}
	return nodeWidth(t.numLeaves)
}

func (t *RatchetTree) resolve (index nodeIndex) []nodeIndex {
	res := []nodeIndex{index}
	if t.nodes[index].node != nil {
		for _, v := range t.nodes[index].node.UnmergedLeaves {
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
		t.nodes[index].setLeafHash(t.cs)
		return
	}
	l := left(index)
	r := right(index, t.size())
	t.nodes[index].setHash(t.cs, t.nodes[l], t.nodes[r] )
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
