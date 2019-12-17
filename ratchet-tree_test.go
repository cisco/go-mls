package mls

import (
	"crypto/rand"
	"testing"

	"github.com/bifurcation/mint/syntax"
)

type testRatchetTree struct {
	Tree *RatchetTree
}

type memberSecret struct {
	secret []byte
}

func newTestRatchetTree(t *testing.T, cs CipherSuite, secrets []memberSecret, creds []Credential) *testRatchetTree {
	ttree := testRatchetTree{Tree: newRatchetTree(cs)}
	if len(secrets) != len(creds) {
		t.Error("secrets and creds size mismatch ")
	}
	for i := 0; i < len(secrets); i++ {
		ix := leafIndex(i)
		priv, err := cs.hpke().Derive(secrets[i].secret)
		if err != nil {
			t.Errorf("private keyy gen failed %v", err)
		}
		ttree.Tree.AddLeaf(ix, &priv.PublicKey, &creds[i])
		ttree.Tree.Merge(ix, priv)
		ttree.Tree.Encap(ix, []byte{}, secrets[i].secret)
	}
	return &ttree
}

func (t *testRatchetTree) checkCredentials() bool {
	for i := 0; i < int(t.Tree.size()); i++ {
		node := t.Tree.Nodes[toNodeIndex(leafIndex(i))]
		if node.Node != nil && node.Node.Cred == nil {
			return false
		}
	}
	return true
}

func (t *testRatchetTree) checkInvariant(from leafIndex) bool {
	inDirPath := map[int]bool{}
	// everyone on the direct path has access to the private key
	dp := dirpath(nodeIndex(from), t.Tree.size())
	dp = append(dp, t.Tree.rootIndex())
	for _, nidx := range dp {
		inDirPath[int(nidx)] = true
		if t.Tree.Nodes[nidx].Node != nil && !t.Tree.Nodes[nidx].hasPrivate() {
			return false
		}
	}
	// .. and nothing else
	for i := 0; i < int(t.Tree.size()); i++ {
		if inDirPath[i] {
			continue
		}
		if t.Tree.Nodes[i].hasPrivate() {
			return false
		}
	}
	return true
}

func genCredential(identity []byte, secret []byte, scheme SignatureScheme) Credential {
	sigPriv, _ := scheme.Derive(secret)

	basicCredential = &BasicCredential{
		Identity:           identity,
		SignatureScheme:    scheme,
		SignaturePublicKey: sigPriv.PublicKey,
	}

	credentialBasic = Credential{Basic: basicCredential}
	return credentialBasic
}

func getRandomBytes(size int) (b []byte, err error) {
	b = make([]byte, size)
	_, err = rand.Read(b)
	return
}

var (
	secretA = unhex("00010203")
	secretB = unhex("04050607")
	secretC = unhex("08090a0b")
	secretD = unhex("0c0d0e0f")

	secretAB = unhex("e8de418a07b497953174c71f5ad83d63d90bc68582a9a340c6023fba536455f4")

	secretABC = unhex("1dbd153c8f2ca387cfc3104b39b0954bbf287bfeb94d2a5bd92e05ff510c2244")

	secretABCD = unhex("ca118da171367f30e5c03e2e651558f55c57fba6319101ccb56f8a34953b25f2")

	credA = genCredential([]byte{'A'}, secretA, Ed25519)
	credB = genCredential([]byte{'B'}, secretB, Ed25519)
	credC = genCredential([]byte{'C'}, secretC, Ed25519)
	credD = genCredential([]byte{'D'}, secretD, Ed25519)

	// Manually computed via a Python script
	hashA    = unhex("30a1ceecab0b150dd15d1a851d7ed36923e872d7344aea6197a8a82f943266f6")
	hashAB   = unhex("bff3b7b65c000086a1f6acf98dc33ae26e82544866b5509f6bfd82f5f188fb09")
	hashABC  = unhex("3f914f333f929c5fe93d33cdf1273b9b23569d16dd21b37b57e4f6f852571d76")
	hashABCD = unhex("67035df4b00b923caa2a2d566a825d7af436afc5d21ff3a9ea97bfde448bcc13")

	msA = memberSecret{secret: secretA}
	msB = memberSecret{secretB}
	msC = memberSecret{secret: secretC}
	msD = memberSecret{secretD}

	allSecrets = []memberSecret{msA, msB, msC, msD}
	allCreds   = []Credential{credA, credB, credC, credD}
)

/////// TESTS

func TestMarshalHashInputForLeafAndParentNodes(t *testing.T) {
	nilInfo := LeafNodeHashInput{
		HashType: 0,
		Info:     nil,
	}

	_, err := syntax.Marshal(nilInfo)
	if err != nil {
		t.Fatalf("LeafNodeHashInput: Marshal error with blank info: %v", err)
	}

	priv, err := supportedSuites[0].hpke().Derive(secretA)
	nonNilInfo := LeafNodeHashInput{
		HashType: 0,
		Info: &LeafNodeInfo{
			Credential: credA,
			PublicKey:  priv.PublicKey,
		},
	}

	_, err = syntax.Marshal(nonNilInfo)
	if err != nil {
		t.Fatalf("LeafNodeHashInput: Marshal error: %v", err)
	}
}

func TestMarshalRatchetTreeMembers(t *testing.T) {
	priv, _ := supportedSuites[0].hpke().Derive(secretA)
	rtn := RatchetTreeNode{
		Cred:           nil,
		PublicKey:      &priv.PublicKey,
		PrivateKey:     &priv,
		UnmergedLeaves: []leafIndex{leafIndex(1)},
		CipherSuite:    supportedSuites[0],
	}

	_, err := syntax.Marshal(rtn)
	if err != nil {
		t.Fatalf("RatchetTreeNode Marshal error: %v", err)
	}

	ortn := OptionalRatchetNode{
		Node: &rtn,
		Hash: []byte{0x01, 0x02, 0x03, 0x04},
	}

	_, err = syntax.Marshal(ortn)
	if err != nil {
		t.Fatalf("OptionalRatchetTreeNode Marshal error: %v", err)
	}

	rt := RatchetTree{
		Nodes:       []OptionalRatchetNode{ortn},
		CipherSuite: supportedSuites[0],
		NumLeaves:   1,
	}
	_, err = syntax.Marshal(rt)
	if err != nil {
		t.Fatalf("RatchetTree Marshal error: %v", err)
	}
}

func TestRatchetTreeOneMember(t *testing.T) {
	ms := memberSecret{
		secret: secretA,
	}
	tree := newTestRatchetTree(t, supportedSuites[0], []memberSecret{ms}, []Credential{credA})
	assertTrue(t, tree.Tree.size() == 1, "size mismatch")
	assertEquals(t, *tree.Tree.GetCredential(leafIndex(0)), credA)
}

func TestRatchetTreeMultipleMembers(t *testing.T) {
	secrets := []memberSecret{
		{secret: secretA},
		{secret: secretB},
		{secret: secretC},
		{secret: secretD},
	}

	tree := newTestRatchetTree(t, supportedSuites[0], secrets, []Credential{credA, credB, credC, credD})
	assertTrue(t, tree.Tree.size() == 4, "size mismatch")
	assertEquals(t, *tree.Tree.GetCredential(leafIndex(0)), credA)
	assertEquals(t, *tree.Tree.GetCredential(leafIndex(1)), credB)
	assertEquals(t, *tree.Tree.GetCredential(leafIndex(2)), credC)
	assertEquals(t, *tree.Tree.GetCredential(leafIndex(3)), credD)
}

func TestRatchetTreeByExtension(t *testing.T) {
	cs := supportedSuites[0]
	tree := newRatchetTree(cs)
	// Add A
	privA, err := cs.hpke().Derive(secretA)
	if err != nil {
		t.Errorf("error deriving private key %v", err)
	}

	tree.AddLeaf(leafIndex(0), &privA.PublicKey, &credA)
	_, rootA := tree.Encap(leafIndex(0), []byte{}, secretA)
	assertByteEquals(t, rootA, secretA)
	assertByteEquals(t, tree.RootHash(), hashA)
	assertEquals(t, *tree.GetCredential(leafIndex(0)), credA)

	// Add B
	privB, err := cs.hpke().Derive(secretB)
	if err != nil {
		t.Errorf("error deriving private key %v", err)
	}
	tree.AddLeaf(leafIndex(1), &privB.PublicKey, &credB)
	_, rootB := tree.Encap(leafIndex(1), []byte{}, secretB)
	assertByteEquals(t, rootB, secretAB)
	assertByteEquals(t, tree.RootHash(), hashAB)
	assertEquals(t, *tree.GetCredential(leafIndex(1)), credB)

	// direct check
	secrets := []memberSecret{msA, msB}
	creds := []Credential{credA, credB}
	directAB := newTestRatchetTree(t, supportedSuites[0], secrets, creds)
	assertDeepEquals(t, directAB.Tree, tree)

	// Add C
	privC, err := cs.hpke().Derive(secretC)
	if err != nil {
		t.Errorf("error deriving private key %v", err)
	}
	tree.AddLeaf(leafIndex(2), &privC.PublicKey, &credC)
	_, rootC := tree.Encap(leafIndex(2), []byte{}, secretC)
	assertByteEquals(t, rootC, secretABC)
	assertEquals(t, *tree.GetCredential(leafIndex(2)), credC)
	assertByteEquals(t, tree.RootHash(), hashABC)

	// direct check
	secrets = []memberSecret{msA, msB, msC}
	creds = []Credential{credA, credB, credC}
	directABC := newTestRatchetTree(t, supportedSuites[0], secrets, creds)
	assertDeepEquals(t, directABC.Tree, tree)

	// Add D
	privD, err := cs.hpke().Derive(secretD)
	if err != nil {
		t.Errorf("error deriving private key %v", err)
	}

	tree.AddLeaf(leafIndex(3), &privD.PublicKey, &credD)
	_, rootD := tree.Encap(leafIndex(3), []byte{}, secretD)
	assertByteEquals(t, rootD, secretABCD)
	assertByteEquals(t, tree.RootHash(), hashABCD)
	assertEquals(t, *tree.GetCredential(leafIndex(0)), credA)
	assertEquals(t, *tree.GetCredential(leafIndex(1)), credB)
	assertEquals(t, *tree.GetCredential(leafIndex(2)), credC)
	assertEquals(t, *tree.GetCredential(leafIndex(3)), credD)

	// direct check
	directABCD := newTestRatchetTree(t, supportedSuites[0], allSecrets, allCreds)
	assertDeepEquals(t, directABCD.Tree, tree)
}

func TestRatchetTreeBySerialization(t *testing.T) {
	before := newTestRatchetTree(t, supportedSuites[0], allSecrets, allCreds)
	after := newRatchetTree(supportedSuites[0])
	enc, err := syntax.Marshal(before.Tree)
	if err != nil {
		t.Fatalf("Tree marshall error %v", err)
	}
	_, err = syntax.Unmarshal(enc, after)
	assertDeepEquals(t, before.Tree, after)
}

func TestRatchetTreeEncryptDecrypt(t *testing.T) {
	size := 5
	cs := supportedSuites[0]
	scheme := Ed25519

	trees := [5]testRatchetTree{
		{Tree: newRatchetTree(cs)},
		{Tree: newRatchetTree(cs)},
		{Tree: newRatchetTree(cs)},
		{Tree: newRatchetTree(cs)},
		{Tree: newRatchetTree(cs)},
	}

	for i := 0; i < size; i++ {
		secret, _ := getRandomBytes(32)
		priv, _ := cs.hpke().Derive(secret)
		pub := priv.PublicKey
		sig, _ := scheme.Derive(secret)
		basicCredential = &BasicCredential{
			Identity:           []byte{byte(i)},
			SignatureScheme:    scheme,
			SignaturePublicKey: sig.PublicKey,
		}

		cred := Credential{Basic: basicCredential}

		for j := 0; j < size; j++ {
			trees[j].Tree.AddLeaf(leafIndex(i), &pub, &cred)
			if i == j {
				trees[j].Tree.Merge(leafIndex(i), secret)
			}
		}
	}

	for i := 0; i < size; i++ {
		//assertDeepEquals(t, *trees[i].Tree, trees[0].Tree)
		assertEquals(t, int(trees[i].Tree.size()), size)
		assertTrue(t, trees[i].checkCredentials(), "credential check failed")
	}
}
