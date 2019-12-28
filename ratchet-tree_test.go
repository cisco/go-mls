package mls

import (
	"crypto/rand"
	"fmt"
	"github.com/bifurcation/mint/syntax"
	"testing"
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
	// run the checks for just the member nodes
	if from&1 == 0 {
		return true
	}
	inDirPath := map[int]bool{}
	// everyone on the direct path has access to the private key
	dp := dirpath(nodeIndex(from), t.Tree.size())
	dp = append(dp, t.Tree.rootIndex())
	for _, nidx := range dp {
		inDirPath[int(nidx)] = true
		if t.Tree.Nodes[nidx].Node != nil && !t.Tree.Nodes[nidx].hasPrivate() {
			fmt.Printf("checkInvariant: dirPath missing privateKey: %v\n", nidx)
			return false
		}
	}
	// .. and nothing else
	for i := 0; i < int(t.Tree.size()); i++ {
		if inDirPath[i] {
			continue
		}
		if t.Tree.Nodes[i].hasPrivate() {
			fmt.Printf("checkInvariant: non dirPath node has the privateKey: %v\n", i)
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
	assertTrue(t, before.Tree.Equals(after), "Tree mismatch")
}


func TestRatchetTreeEncryptDecrypt(t *testing.T) {
	const size = 4
	cs := supportedSuites[0]
	scheme := Ed25519

	trees := [size]testRatchetTree{
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
		assertEquals(t, int(trees[i].Tree.size()), size)
		assertTrue(t, trees[i].checkCredentials(), "credential check failed")
		assertTrue(t, trees[i].checkInvariant(leafIndex(i*2)), "check invariant failed")
	}

	// verify encrypt/decrypt
	for i := 0; i < size; i++ {
		secret, _ := getRandomBytes(32)
		dp, rootSecret := trees[i].Tree.Encap(leafIndex(i), []byte{}, secret)
		for j := 0; j < size; j++ {
			if i == j {
				continue
			}
			decryptedSecret := trees[j].Tree.Decap(leafIndex(i), []byte{}, dp)
			assertByteEquals(t, rootSecret, decryptedSecret)
		}
	}

}
