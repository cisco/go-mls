package mls

import "testing"

// Add some tests for message structures for leaf and parent hash inputs

func TestMarshalUnmarshalLeafNode(t *testing.T) {
}


type testRatchetTree struct {
	Tree *RatchetTree
}

type memberSecret struct {
	secret []byte
}

func newTestRatchetTree(t *testing.T, cs CipherSuite, secrets []memberSecret, creds []Credential) testRatchetTree {
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
		//t.Logf("Running tree setup for index %v", i)
		ttree.Tree.AddLeaf(ix, &priv.PublicKey, &creds[i])
		ttree.Tree.Merge(ix, priv)
		ttree.Tree.Encap(ix, []byte{}, secrets[i].secret)
	}
	return ttree
}

func genCredential(identity []byte, scheme SignatureScheme,) Credential {
	sigPriv, _ := scheme.Generate()

	basicCredential = &BasicCredential{
		Identity:           identity,
		SignatureScheme:    scheme,
		SignaturePublicKey: sigPriv.PublicKey,
	}

	credentialBasic = Credential{Basic: basicCredential}
	return credentialBasic
}

var (

	secretA = unhex("00010203")
	secretB = unhex("04050607")
	secretC = unhex("08090a0b")
	secretD = unhex("0c0d0e0f")

	secretAB = unhex(
	"e8de418a07b497953174c71f5ad83d63d90bc68582a9a340c6023fba536455f4")

    credA = genCredential([]byte{'A'}, Ed25519)
	credB = genCredential([]byte{'B'}, Ed25519)
	credC = genCredential([]byte{'C'}, Ed25519)
	credD = genCredential([]byte{'D'}, Ed25519)

	// Manually computed via a Python script
	hashA = unhex("30a1ceecab0b150dd15d1a851d7ed36923e872d7344aea6197a8a82f943266f6")
    hashAB = unhex("bff3b7b65c000086a1f6acf98dc33ae26e82544866b5509f6bfd82f5f188fb09")

)

func TestRatchetTreeOneMember(t *testing.T) {
	ms := memberSecret{
		secret: secretA,
	}
	tree := newTestRatchetTree(t, supportedSuites[0], []memberSecret{ms}, []Credential{credA})
	assertTrue(t, tree.Tree.size() ==1, "size mismatch")
	assertEquals(t, *tree.Tree.GetCredential(leafIndex(0)), credA)
}

func TestRatchetTreeMultipleMembers(t *testing.T) {
	secrets := []memberSecret{
		{secret:secretA},
		{secret:secretB},
		{secret:secretC},
		{secret:secretD},
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
	// todo: refactor to remove duplication
	// Add A
	privA, err := cs.hpke().Derive(secretA)
	if err != nil {
		t.Errorf("error deriving private key %v", err)
	}

	tree.AddLeaf(leafIndex(0), &privA.PublicKey, &credA)
	_, rootA := tree.Encap(leafIndex(0), []byte{}, secretA)

	assertByteEquals(t, rootA, secretA)
	//assertByteEquals(t, tree.RootHash(), hashA)
	assertEquals(t, *tree.GetCredential(leafIndex(0)), credA)

	// Add B
	privB, err := cs.hpke().Derive(secretB)
	if err != nil {
		t.Errorf("error deriving private key %v",err)
	}
	tree.AddLeaf(leafIndex(1), &privB.PublicKey, &credB)
	//_, rootB := tree.Encap(leafIndex(1), []byte{}, secretB)
	tree.Encap(leafIndex(1), []byte{}, secretB)
	assertEquals(t, *tree.GetCredential(leafIndex(1)), credB)

	//assertByteEquals(t, tree.RootHash(), hashAB)
	//assertByteEquals(t, rootB, secretAB)


}
