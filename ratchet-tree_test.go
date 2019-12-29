package mls

import (
	"crypto/rand"
	"fmt"
	"github.com/bifurcation/mint/syntax"
	"testing"
)

func newTestRatchetTree(t *testing.T, cs CipherSuite, secrets [][]byte, creds []Credential) *RatchetTree {
	tree := newRatchetTree(cs)
	if len(secrets) != len(creds) {
		t.Error("secrets and creds size mismatch")
	}
	for i := 0; i < len(secrets); i++ {
		ix := leafIndex(i)
		priv, err := cs.hpke().Derive(secrets[i])
		if err != nil {
			t.Errorf("private keyy gen failed %v", err)
		}
		tree.AddLeaf(ix, &priv.PublicKey, &creds[i])
		tree.Merge(ix, secrets[i])
		tree.Encap(ix, []byte{}, secrets[i])
	}
	return tree
}

func (t *RatchetTree) checkCredentials() bool {
	for i := 0; i < int(t.size()); i++ {
		node := t.Nodes[toNodeIndex(leafIndex(i))]
		if node.Node != nil && node.Node.Credential == nil {
			return false
		}
	}
	return true
}

func (t *RatchetTree) checkInvariant(from leafIndex) bool {
	// run the checks for just the member nodes
	if from&1 == 0 {
		return true
	}
	inDirPath := map[int]bool{}

	// everyone on the direct path has access to the private key
	dp := dirpath(nodeIndex(from), t.size())
	dp = append(dp, t.rootIndex())
	for _, nidx := range dp {
		inDirPath[int(nidx)] = true
		if t.Nodes[nidx].Node != nil && !t.Nodes[nidx].hasPrivate() {
			return false
		}
	}

	// .. and nothing else
	for i := 0; i < int(t.size()); i++ {
		if inDirPath[i] {
			continue
		}
		if t.Nodes[i].hasPrivate() {
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

	allSecrets = [][]byte{secretA, secretB, secretC, secretD}
	allCreds   = []Credential{credA, credB, credC, credD}
)

/////// TESTS

func TestRatchetTreeOneMember(t *testing.T) {
	tree := newTestRatchetTree(t, supportedSuites[0], [][]byte{secretA}, []Credential{credA})
	assertTrue(t, tree.size() == 1, "size mismatch")
	assertEquals(t, *tree.GetCredential(leafIndex(0)), credA)
}

func TestRatchetTreeMultipleMembers(t *testing.T) {
	tree := newTestRatchetTree(t, supportedSuites[0], allSecrets, allCreds)
	assertTrue(t, tree.size() == 4, "size mismatch")
	assertEquals(t, *tree.GetCredential(leafIndex(0)), credA)
	assertEquals(t, *tree.GetCredential(leafIndex(1)), credB)
	assertEquals(t, *tree.GetCredential(leafIndex(2)), credC)
	assertEquals(t, *tree.GetCredential(leafIndex(3)), credD)
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
	directAB := newTestRatchetTree(t, supportedSuites[0], allSecrets[:2], allCreds[:2])
	assertTrue(t, directAB.Equals(tree), "TreeAB mismatch")

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
	directABC := newTestRatchetTree(t, supportedSuites[0], allSecrets[:3], allCreds[:3])
	assertTrue(t, directABC.Equals(tree), "TreeABC mismatch")

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
	assertTrue(t, directABCD.Equals(tree), "TreeABCD mismatch")
}

func TestRatchetTreeBySerialization(t *testing.T) {
	before := newTestRatchetTree(t, supportedSuites[0], allSecrets, allCreds)
	after := newRatchetTree(supportedSuites[0])
	enc, err := syntax.Marshal(before)
	assertNotError(t, err, "Tree marshal error")

	_, err = syntax.Unmarshal(enc, after)
	assertTrue(t, before.Equals(after), "Tree mismatch")
}

func TestRatchetTreeEncryptDecrypt(t *testing.T) {
	const size = 4
	cs := supportedSuites[0]
	scheme := Ed25519

	// TODO use make()
	// TODO elminate the testRatchetTree type
	trees := make([]*RatchetTree, size)
	for i := range trees {
		trees[i] = newRatchetTree(cs)
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

		for j, tree := range trees {
			tree.AddLeaf(leafIndex(i), &pub, &cred)
			if i == j {
				tree.Merge(leafIndex(i), secret)
			}
		}
	}

	// Verify that all trees are equal and the invariants are satisfied
	for i, tree := range trees {
		assertTrue(t, tree.Equals(trees[0]), fmt.Sprintf("Tree %d differs", i))
		assertEquals(t, int(tree.size()), size)
		assertTrue(t, tree.checkCredentials(), "credential check failed")
		assertTrue(t, tree.checkInvariant(leafIndex(i*2)), "check invariant failed")
	}

	// verify encrypt/decrypt
	for i, srcTree := range trees {
		secret, _ := getRandomBytes(32)
		path, rootSecret := srcTree.Encap(leafIndex(i), []byte{}, secret)
		for j, dstTree := range trees {
			if i == j {
				continue
			}
			decryptedSecret := dstTree.Decap(leafIndex(i), []byte{}, path)
			assertByteEquals(t, rootSecret, decryptedSecret)
			assertTrue(t, srcTree.Equals(dstTree), "Failed update on decap()")
		}
	}
}
