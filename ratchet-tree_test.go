package mls

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/bifurcation/mint/syntax"
	"github.com/stretchr/testify/require"
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
	/* TODO(RLB): Recompute and re-enable once tree structure stabilizes for draft-09
	hashA    = unhex("30a1ceecab0b150dd15d1a851d7ed36923e872d7344aea6197a8a82f943266f6")
	hashAB   = unhex("bff3b7b65c000086a1f6acf98dc33ae26e82544866b5509f6bfd82f5f188fb09")
	hashABC  = unhex("3f914f333f929c5fe93d33cdf1273b9b23569d16dd21b37b57e4f6f852571d76")
	hashABCD = unhex("67035df4b00b923caa2a2d566a825d7af436afc5d21ff3a9ea97bfde448bcc13")
	*/

	allSecrets = [][]byte{secretA, secretB, secretC, secretD}
	allCreds   = []Credential{credA, credB, credC, credD}
)

/////// TESTS

func TestRatchetTreeOneMember(t *testing.T) {
	tree := newTestRatchetTree(t, supportedSuites[0], [][]byte{secretA}, []Credential{credA})
	require.Equal(t, tree.size(), leafCount(1))
	require.Equal(t, *tree.GetCredential(leafIndex(0)), credA)
}

func TestRatchetTreeMultipleMembers(t *testing.T) {
	tree := newTestRatchetTree(t, supportedSuites[0], allSecrets, allCreds)
	require.Equal(t, tree.size(), leafCount(4))
	require.Equal(t, *tree.GetCredential(leafIndex(0)), credA)
	require.Equal(t, *tree.GetCredential(leafIndex(1)), credB)
	require.Equal(t, *tree.GetCredential(leafIndex(2)), credC)
	require.Equal(t, *tree.GetCredential(leafIndex(3)), credD)
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
	require.Equal(t, rootA, secretA)
	// XXX require.Equal(t, tree.RootHash(), hashA)
	require.Equal(t, *tree.GetCredential(leafIndex(0)), credA)

	// Add B
	privB, err := cs.hpke().Derive(secretB)
	if err != nil {
		t.Errorf("error deriving private key %v", err)
	}
	tree.AddLeaf(leafIndex(1), &privB.PublicKey, &credB)
	_, rootB := tree.Encap(leafIndex(1), []byte{}, secretB)
	require.Equal(t, rootB, secretAB)
	// XXX require.Equal(t, tree.RootHash(), hashAB)
	require.Equal(t, *tree.GetCredential(leafIndex(1)), credB)

	// direct check
	directAB := newTestRatchetTree(t, supportedSuites[0], allSecrets[:2], allCreds[:2])
	require.True(t, directAB.Equals(tree))

	// Add C
	privC, err := cs.hpke().Derive(secretC)
	if err != nil {
		t.Errorf("error deriving private key %v", err)
	}
	tree.AddLeaf(leafIndex(2), &privC.PublicKey, &credC)
	_, rootC := tree.Encap(leafIndex(2), []byte{}, secretC)
	require.Equal(t, rootC, secretABC)
	// XXX require.Equal(t, *tree.GetCredential(leafIndex(2)), credC)
	// XXX require.Equal(t, tree.RootHash(), hashABC)

	// direct check
	directABC := newTestRatchetTree(t, supportedSuites[0], allSecrets[:3], allCreds[:3])
	require.True(t, directABC.Equals(tree))

	// Add D
	privD, err := cs.hpke().Derive(secretD)
	if err != nil {
		t.Errorf("error deriving private key %v", err)
	}

	tree.AddLeaf(leafIndex(3), &privD.PublicKey, &credD)
	_, rootD := tree.Encap(leafIndex(3), []byte{}, secretD)
	require.Equal(t, rootD, secretABCD)
	// XXX require.Equal(t, tree.RootHash(), hashABCD)
	require.Equal(t, *tree.GetCredential(leafIndex(0)), credA)
	require.Equal(t, *tree.GetCredential(leafIndex(1)), credB)
	require.Equal(t, *tree.GetCredential(leafIndex(2)), credC)
	require.Equal(t, *tree.GetCredential(leafIndex(3)), credD)

	// direct check
	directABCD := newTestRatchetTree(t, supportedSuites[0], allSecrets, allCreds)
	require.True(t, directABCD.Equals(tree))
}

func TestRatchetTreeBySerialization(t *testing.T) {
	before := newTestRatchetTree(t, supportedSuites[0], allSecrets, allCreds)
	after := newRatchetTree(supportedSuites[0])
	enc, err := before.MarshalTLS()
	require.Nil(t, err)
	_, err = after.UnmarshalTLS(enc)
	require.True(t, before.Equals(after))
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
		require.True(t, tree.Equals(trees[0]), fmt.Sprintf("Tree %d differs", i))
		require.Equal(t, int(tree.size()), size)
		require.True(t, tree.checkCredentials())
		require.True(t, tree.checkInvariant(leafIndex(i*2)))
	}

	// verify encrypt/decrypt
	for i, srcTree := range trees {
		secret, _ := getRandomBytes(32)
		path, rootSecret := srcTree.Encap(leafIndex(i), []byte{}, secret)
		for j, dstTree := range trees {
			if i == j {
				continue
			}

			decryptedSecret, err := dstTree.Decap(leafIndex(i), []byte{}, path)
			require.Nil(t, err)
			require.Equal(t, rootSecret, decryptedSecret)
			require.True(t, srcTree.Equals(dstTree))
		}
	}
}

func TestRatchetTreeSecrets(t *testing.T) {
	suite := supportedSuites[0]

	// Form a tree and split out the secret bits
	tree := newTestRatchetTree(t, suite, allSecrets, allCreds)
	secrets := tree.GetSecrets()

	// Marshal the private and public parts
	marshaledPub, err := syntax.Marshal(tree)
	require.Nil(t, err)

	marshaledPriv, err := syntax.Marshal(secrets)
	require.Nil(t, err)

	// Unmarshal the private and public parts
	tree2 := newRatchetTree(suite)
	secrets2 := TreeSecrets{}

	_, err = syntax.Unmarshal(marshaledPub, tree2)
	require.Nil(t, err)

	_, err = syntax.Unmarshal(marshaledPriv, &secrets2)
	require.Nil(t, err)

	// Reassemble the tree
	tree2.SetSecrets(secrets2)

	// Compare public and private contents
	require.Equal(t, tree, tree2)
}

func TestRatchetTree_Clone(t *testing.T) {
	tree := newTestRatchetTree(t, supportedSuites[0], allSecrets, allCreds)
	require.Equal(t, tree.size(), leafCount(4))

	cloned := tree.clone()
	require.Equal(t, cloned.size(), leafCount(4))
	require.Equal(t, *cloned.GetCredential(leafIndex(0)), credA)
	require.Equal(t, *cloned.GetCredential(leafIndex(1)), credB)
	require.Equal(t, *cloned.GetCredential(leafIndex(2)), credC)
	require.Equal(t, *cloned.GetCredential(leafIndex(3)), credD)

	require.True(t, tree.Equals(cloned))
}

///
/// Test Vectors
///

type OptionalPublicKey struct {
	Data []byte `tls:"head=1"`
}

type TreeNode struct {
	PubKey *OptionalPublicKey `tls:"optional"`
	Hash   []byte             `tls:"head=1"`
}

type RatchetTreeCase struct {
	CipherSuite     CipherSuite
	SignatureScheme SignatureScheme

	Credentials []Credential `tls:"head=4"`
	Trees       [][]TreeNode `tls:"head=4"`
}

type testSecret struct {
	Data []byte `tls:"head=1"`
}

type RatchetTreeVectors struct {
	LeafSecrets []testSecret      `tls:"head=4"`
	Credentials []Credential      `tls:"head=4"`
	Cases       []RatchetTreeCase `tls:"head=4"`
}

func treeToTreeNode(tree *RatchetTree) []TreeNode {

	nodes := tree.Nodes
	tc := make([]TreeNode, len(nodes))
	for i := 0; i < len(nodes); i++ {
		tc[i].Hash = nodes[i].Hash
		if !nodes[i].blank() {
			tc[i].PubKey = &OptionalPublicKey{
				Data: []byte{},
			}
			tc[i].PubKey.Data = nodes[i].Node.PublicKey.Data
		}
	}
	return tc
}

func generateRatchetTreeVectors(t *testing.T) []byte {
	var tv RatchetTreeVectors
	suites := []CipherSuite{P256_AES128GCM_SHA256_P256, X25519_AES128GCM_SHA256_Ed25519}
	var leaves = 10

	tv.LeafSecrets = []testSecret{}
	for i := 0; i < leaves; i++ {
		ts := testSecret{Data: []byte{byte(i)}}
		tv.LeafSecrets = append(tv.LeafSecrets, ts)
	}

	for i := range suites {
		var tc RatchetTreeCase
		suite := suites[i]
		tc.CipherSuite = suite
		tree := newRatchetTree(suite)

		// add leaves
		for j := 0; j < leaves; j++ {
			id := []byte{byte(j)}
			sigPriv, err := suite.scheme().Derive(id)
			require.Nil(t, err)
			sigPub := sigPriv.PublicKey
			bc := &BasicCredential{
				Identity:           id,
				SignatureScheme:    suite.scheme(),
				SignaturePublicKey: sigPub,
			}
			cred := Credential{Basic: bc}
			tc.Credentials = append(tc.Credentials, cred)
			priv, err := suite.hpke().Derive(tv.LeafSecrets[j].Data)
			require.Nil(t, err)
			err = tree.AddLeaf(leafIndex(j), &priv.PublicKey, &cred)
			require.Nil(t, err)
			tree.Encap(leafIndex(j), []byte{}, tv.LeafSecrets[j].Data)
			tc.Trees = append(tc.Trees, treeToTreeNode(tree))
		}

		// blank out the even numbered leaves
		for j := 0; j < leaves; j += 2 {
			err := tree.BlankPath(leafIndex(j), true)
			require.Nil(t, err)
			tc.Trees = append(tc.Trees, treeToTreeNode(tree))
		}

		tv.Cases = append(tv.Cases, tc)

	}

	vec, err := syntax.Marshal(tv)
	require.Nil(t, err)
	return vec
}

func requireTreesEqual(t *testing.T, tn []TreeNode, tree *RatchetTree) {
	nodes := tree.Nodes
	require.Equal(t, len(tn), len(nodes))
	for i := 0; i < len(tn); i++ {
		require.True(t, bytes.Equal(tn[i].Hash, nodes[i].Hash))
		if !nodes[i].blank() {
			require.Equal(t, tn[i].PubKey.Data, nodes[i].Node.PublicKey.Data)
		} else {
			require.Nil(t, tn[i].PubKey)
		}
	}
}

func verifyRatchetTreeVectors(t *testing.T, data []byte) {
	var tv RatchetTreeVectors
	_, err := syntax.Unmarshal(data, &tv)
	require.Nil(t, err)

	for _, tc := range tv.Cases {
		suite := tc.CipherSuite
		tree := newRatchetTree(suite)
		var tci = 0
		for i := 0; i < len(tv.LeafSecrets); i++ {
			priv, err := suite.hpke().Derive(tv.LeafSecrets[i].Data)
			require.Nil(t, err)
			err = tree.AddLeaf(leafIndex(i), &priv.PublicKey, &tc.Credentials[i])
			require.Nil(t, err)
			tree.Encap(leafIndex(i), []byte{}, tv.LeafSecrets[i].Data)
			requireTreesEqual(t, tc.Trees[tci], tree)
			tci += 1
		}

		// blank even numbered leaves
		for j := 0; j < len(tv.LeafSecrets); j += 2 {
			err := tree.BlankPath(leafIndex(j), true)
			require.Nil(t, err)
			requireTreesEqual(t, tc.Trees[tci], tree)
			tci += 1
		}
	}
}
