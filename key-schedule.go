package mls

import (
	"fmt"
)

type keyAndNonce struct {
	Key   []byte `tls:"head=1"`
	Nonce []byte `tls:"head=1"`
}

func (k keyAndNonce) clone(suite CipherSuite) keyAndNonce {
	cloned := keyAndNonce{
		Key:   make([]byte, suite.constants().KeySize),
		Nonce: make([]byte, suite.constants().NonceSize),
	}
	copy(cloned.Key, k.Key)
	copy(cloned.Nonce, k.Nonce)
	return cloned
}

func zeroize(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

///
/// Hash ratchet
///

type hashRatchet struct {
	Suite          CipherSuite
	Node           nodeIndex
	NextSecret     []byte
	NextGeneration uint32
	Cache          map[uint32]keyAndNonce
	KeySize        int
	NonceSize      int
	SecretSize     int
}

func newHashRatchet(suite CipherSuite, node nodeIndex, baseSecret []byte) *hashRatchet {
	return &hashRatchet{
		Suite:          suite,
		Node:           node,
		NextSecret:     baseSecret,
		NextGeneration: 0,
		Cache:          map[uint32]keyAndNonce{},
		KeySize:        suite.constants().KeySize,
		NonceSize:      suite.constants().NonceSize,
		SecretSize:     suite.constants().SecretSize,
	}
}

func (hr *hashRatchet) Next() (uint32, keyAndNonce) {
	key := hr.Suite.deriveAppSecret(hr.NextSecret, "app-key", hr.Node, hr.NextGeneration, hr.KeySize)
	nonce := hr.Suite.deriveAppSecret(hr.NextSecret, "app-nonce", hr.Node, hr.NextGeneration, hr.NonceSize)
	secret := hr.Suite.deriveAppSecret(hr.NextSecret, "app-secret", hr.Node, hr.NextGeneration, hr.SecretSize)

	generation := hr.NextGeneration

	hr.NextGeneration += 1
	zeroize(hr.NextSecret)
	hr.NextSecret = secret

	hr.Cache[generation] = keyAndNonce{key, nonce}
	return generation, hr.Cache[generation].clone(hr.Suite)
}

func (hr *hashRatchet) Get(generation uint32) (keyAndNonce, error) {
	if kn, ok := hr.Cache[generation]; ok {
		return kn, nil
	}

	if hr.NextGeneration > generation {
		return keyAndNonce{}, fmt.Errorf("Request for expired key")
	}

	for hr.NextGeneration < generation {
		hr.Next()
	}

	_, kn := hr.Next()
	return kn, nil
}

func (hr *hashRatchet) Erase(generation uint32) {
	if _, ok := hr.Cache[generation]; !ok {
		return
	}

	zeroize(hr.Cache[generation].Key)
	zeroize(hr.Cache[generation].Nonce)
	delete(hr.Cache, generation)
}

///
/// Base key sources
///

type baseKeySource interface {
	Suite() CipherSuite
	Get(sender leafIndex) []byte
}

type noFSBaseKeySource struct {
	CipherSuite CipherSuite
	RootSecret  []byte
}

func newNoFSBaseKeySource(suite CipherSuite, rootSecret []byte) *noFSBaseKeySource {
	return &noFSBaseKeySource{suite, rootSecret}
}

func (nfbks *noFSBaseKeySource) Suite() CipherSuite {
	return nfbks.CipherSuite
}

func (nfbks *noFSBaseKeySource) Get(sender leafIndex) []byte {
	secretSize := nfbks.CipherSuite.constants().SecretSize
	return nfbks.CipherSuite.deriveAppSecret(nfbks.RootSecret, "hs-secret", toNodeIndex(sender), 0, secretSize)
}

type treeBaseKeySource struct {
	CipherSuite CipherSuite
	SecretSize  int
	Root        nodeIndex
	Size        leafCount
	Secrets     map[nodeIndex][]byte
}

func newTreeBaseKeySource(suite CipherSuite, size leafCount, rootSecret []byte) *treeBaseKeySource {
	tbks := &treeBaseKeySource{
		CipherSuite: suite,
		SecretSize:  suite.constants().SecretSize,
		Root:        root(size),
		Size:        size,
		Secrets:     map[nodeIndex][]byte{},
	}

	tbks.Secrets[tbks.Root] = rootSecret
	return tbks
}

func (tbks *treeBaseKeySource) Suite() CipherSuite {
	return tbks.CipherSuite
}

func (tbks *treeBaseKeySource) Get(sender leafIndex) []byte {
	// Find an ancestor that is populated
	senderNode := toNodeIndex(sender)
	d := dirpath(senderNode, tbks.Size)
	found := false
	curr := 0
	for i, node := range d {
		if _, ok := tbks.Secrets[node]; ok {
			found = true
			curr = i
			break
		}
	}

	if !found {
		panic("Unable to find source for base key")
	}

	// Derive down
	for ; curr > 0; curr -= 1 {
		node := d[curr]
		L := left(node)
		R := right(node, tbks.Size)

		secret := tbks.Secrets[node]
		tbks.Secrets[L] = tbks.CipherSuite.deriveAppSecret(secret, "tree", L, 0, tbks.SecretSize)
		tbks.Secrets[R] = tbks.CipherSuite.deriveAppSecret(secret, "tree", R, 0, tbks.SecretSize)
		zeroize(tbks.Secrets[node])
		delete(tbks.Secrets, node)
	}

	// Copy and return the leaf
	out := make([]byte, tbks.SecretSize)
	copy(out, tbks.Secrets[senderNode])
	zeroize(tbks.Secrets[senderNode])
	delete(tbks.Secrets, senderNode)

	return out
}

func (tbks *treeBaseKeySource) dump() {
	w := nodeWidth(tbks.Size)
	fmt.Println("=== tbks ===")
	for i := nodeIndex(0); i < nodeIndex(w); i += 1 {
		s, ok := tbks.Secrets[i]
		if ok {
			fmt.Printf("  %3x [%x]\n", i, s)
		} else {
			fmt.Printf("  %3x _\n", i)
		}
	}
}

///
/// Group key source
///

type groupKeySource struct {
	Base     baseKeySource
	Ratchets map[leafIndex]*hashRatchet
}

func newGroupKeySource(base baseKeySource) *groupKeySource {
	return &groupKeySource{base, map[leafIndex]*hashRatchet{}}
}

func (gks groupKeySource) ratchet(sender leafIndex) *hashRatchet {
	if r, ok := gks.Ratchets[sender]; ok {
		return r
	}

	baseSecret := gks.Base.Get(sender)
	gks.Ratchets[sender] = newHashRatchet(gks.Base.Suite(), toNodeIndex(sender), baseSecret)
	return gks.Ratchets[sender]
}

func (gks groupKeySource) Next(sender leafIndex) (uint32, keyAndNonce) {
	return gks.ratchet(sender).Next()
}

func (gks groupKeySource) Get(sender leafIndex, generation uint32) (keyAndNonce, error) {
	return gks.ratchet(sender).Get(generation)
}

func (gks groupKeySource) Erase(sender leafIndex, generation uint32) {
	gks.ratchet(sender).Erase(generation)
}

///
/// First epoch
///

type firstEpoch struct {
	Suite           CipherSuite
	InitSecret      []byte
	GroupInfoSecret []byte
	GroupInfoKey    []byte
	GroupInfoNonce  []byte
}

func newFirstEpoch(suite CipherSuite, initSecret []byte) *firstEpoch {
	secretSize := suite.constants().SecretSize
	keySize := suite.constants().KeySize
	nonceSize := suite.constants().NonceSize

	groupInfoSecret := suite.hkdfExpandLabel(initSecret, "group info", []byte{}, secretSize)
	groupInfoKey := suite.hkdfExpandLabel(groupInfoSecret, "key", []byte{}, keySize)
	groupInfoNonce := suite.hkdfExpandLabel(groupInfoSecret, "nonce", []byte{}, nonceSize)

	return &firstEpoch{suite, initSecret, groupInfoSecret, groupInfoKey, groupInfoNonce}
}

func (fe firstEpoch) Next(size leafCount, updateSecret, context []byte) keyScheduleEpoch {
	epochSecret := fe.Suite.hkdfExtract(fe.InitSecret, updateSecret)
	return newKeyScheduleEpoch(fe.Suite, size, epochSecret, context)
}

///
/// Key schedule epoch
///

type keyScheduleEpoch struct {
	Suite             CipherSuite
	EpochSecret       []byte
	SenderDataSecret  []byte
	SenderDataKey     []byte
	HandshakeSecret   []byte
	HandshakeKeys     *groupKeySource
	ApplicationSecret []byte
	ApplicationKeys   *groupKeySource
	ConfirmationKey   []byte
	InitSecret        []byte
}

func newKeyScheduleEpoch(suite CipherSuite, size leafCount, epochSecret, context []byte) keyScheduleEpoch {
	senderDataSecret := suite.deriveSecret(epochSecret, "sender data", context)
	handshakeSecret := suite.deriveSecret(epochSecret, "handshake", context)
	applicationSecret := suite.deriveSecret(epochSecret, "app", context)
	confirmationKey := suite.deriveSecret(epochSecret, "confirm", context)
	initSecret := suite.deriveSecret(epochSecret, "init", context)

	senderDataKey := suite.hkdfExpandLabel(senderDataSecret, "sd key", []byte{}, suite.constants().KeySize)
	handshakeBaseKeys := newNoFSBaseKeySource(suite, handshakeSecret)
	applicationBaseKeys := newTreeBaseKeySource(suite, size, applicationSecret)

	return keyScheduleEpoch{
		Suite:             suite,
		EpochSecret:       epochSecret,
		SenderDataSecret:  senderDataSecret,
		SenderDataKey:     senderDataKey,
		HandshakeSecret:   handshakeSecret,
		HandshakeKeys:     newGroupKeySource(handshakeBaseKeys),
		ApplicationSecret: applicationSecret,
		ApplicationKeys:   newGroupKeySource(applicationBaseKeys),
		ConfirmationKey:   confirmationKey,
		InitSecret:        initSecret,
	}
}

func (kse *keyScheduleEpoch) Next(size leafCount, updateSecret, context []byte) keyScheduleEpoch {
	epochSecret := kse.Suite.hkdfExtract(kse.InitSecret, updateSecret)
	return newKeyScheduleEpoch(kse.Suite, size, epochSecret, context)
}
