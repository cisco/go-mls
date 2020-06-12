package mls

import (
	"fmt"

	"github.com/cisco/go-tls-syntax"
)

type keyAndNonce struct {
	Key   []byte `tls:"head=1"`
	Nonce []byte `tls:"head=1"`
}

func (k keyAndNonce) clone() keyAndNonce {
	return keyAndNonce{
		Key:   dup(k.Key),
		Nonce: dup(k.Nonce),
	}
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
	Node           NodeIndex
	NextSecret     []byte `tls:"head=1"`
	NextGeneration uint32
	Cache          map[uint32]keyAndNonce `tls:"head=4"`
	KeySize        uint32
	NonceSize      uint32
	SecretSize     uint32
}

func newHashRatchet(suite CipherSuite, node NodeIndex, baseSecret []byte) *hashRatchet {
	return &hashRatchet{
		Suite:          suite,
		Node:           node,
		NextSecret:     baseSecret,
		NextGeneration: 0,
		Cache:          map[uint32]keyAndNonce{},
		KeySize:        uint32(suite.Constants().KeySize),
		NonceSize:      uint32(suite.Constants().NonceSize),
		SecretSize:     uint32(suite.Constants().SecretSize),
	}
}

func (hr *hashRatchet) Next() (uint32, keyAndNonce) {
	key := hr.Suite.deriveAppSecret(hr.NextSecret, "app-key", hr.Node, hr.NextGeneration, int(hr.KeySize))
	nonce := hr.Suite.deriveAppSecret(hr.NextSecret, "app-nonce", hr.Node, hr.NextGeneration, int(hr.NonceSize))
	secret := hr.Suite.deriveAppSecret(hr.NextSecret, "app-secret", hr.Node, hr.NextGeneration, int(hr.SecretSize))

	generation := hr.NextGeneration

	hr.NextGeneration += 1
	zeroize(hr.NextSecret)
	hr.NextSecret = secret

	kn := keyAndNonce{key, nonce}
	hr.Cache[generation] = kn
	return generation, kn.clone()
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
	Get(sender LeafIndex) []byte
}

type noFSBaseKeySource struct {
	CipherSuite CipherSuite
	RootSecret  []byte `tls:"head=1"`
}

func newNoFSBaseKeySource(suite CipherSuite, rootSecret []byte) *noFSBaseKeySource {
	return &noFSBaseKeySource{suite, rootSecret}
}

func (nfbks *noFSBaseKeySource) Suite() CipherSuite {
	return nfbks.CipherSuite
}

func (nfbks *noFSBaseKeySource) Get(sender LeafIndex) []byte {
	secretSize := nfbks.CipherSuite.Constants().SecretSize
	return nfbks.CipherSuite.deriveAppSecret(nfbks.RootSecret, "hs-secret", toNodeIndex(sender), 0, secretSize)
}

type Bytes1 []byte

func (b Bytes1) MarshalTLS() ([]byte, error) {
	return syntax.Marshal(struct {
		Data []byte `tls:"head=1"`
	}{b})
}

func (b *Bytes1) UnmarshalTLS(data []byte) (int, error) {
	tmp := struct {
		Data []byte `tls:"head=1"`
	}{}
	read, err := syntax.Unmarshal(data, &tmp)
	if err != nil {
		return read, err
	}

	*b = dup(tmp.Data)
	return read, nil
}

type treeBaseKeySource struct {
	CipherSuite CipherSuite
	SecretSize  uint32
	Root        NodeIndex
	Size        LeafCount
	Secrets     map[NodeIndex]Bytes1 `tls:"head=4"`
}

func newTreeBaseKeySource(suite CipherSuite, size LeafCount, rootSecret []byte) *treeBaseKeySource {
	tbks := &treeBaseKeySource{
		CipherSuite: suite,
		SecretSize:  uint32(suite.Constants().SecretSize),
		Root:        root(size),
		Size:        size,
		Secrets:     map[NodeIndex]Bytes1{},
	}

	tbks.Secrets[tbks.Root] = rootSecret
	return tbks
}

func (tbks *treeBaseKeySource) Suite() CipherSuite {
	return tbks.CipherSuite
}

func (tbks *treeBaseKeySource) Get(sender LeafIndex) []byte {
	// Find an ancestor that is populated
	senderNode := toNodeIndex(sender)
	d := dirpath(senderNode, tbks.Size)
	d = append([]NodeIndex{senderNode}, d...)
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
		tbks.Secrets[L] = tbks.CipherSuite.deriveAppSecret(secret, "tree", L, 0, int(tbks.SecretSize))
		tbks.Secrets[R] = tbks.CipherSuite.deriveAppSecret(secret, "tree", R, 0, int(tbks.SecretSize))
		zeroize(tbks.Secrets[node])
		delete(tbks.Secrets, node)
	}

	// Copy and return the leaf
	out := dup(tbks.Secrets[senderNode])
	zeroize(tbks.Secrets[senderNode])
	delete(tbks.Secrets, senderNode)
	return out
}

func (tbks *treeBaseKeySource) dump() {
	w := nodeWidth(tbks.Size)
	fmt.Println("=== tbks ===")
	for i := NodeIndex(0); i < NodeIndex(w); i += 1 {
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
	Ratchets map[LeafIndex]*hashRatchet
}

func (gks groupKeySource) ratchet(sender LeafIndex) *hashRatchet {
	if r, ok := gks.Ratchets[sender]; ok {
		return r
	}

	baseSecret := gks.Base.Get(sender)
	gks.Ratchets[sender] = newHashRatchet(gks.Base.Suite(), toNodeIndex(sender), baseSecret)
	return gks.Ratchets[sender]
}

func (gks groupKeySource) Next(sender LeafIndex) (uint32, keyAndNonce) {
	return gks.ratchet(sender).Next()
}

func (gks groupKeySource) Get(sender LeafIndex, generation uint32) (keyAndNonce, error) {
	return gks.ratchet(sender).Get(generation)
}

func (gks groupKeySource) Erase(sender LeafIndex, generation uint32) {
	gks.ratchet(sender).Erase(generation)
}

///
/// GroupInfo keys
///

func groupInfoKeyAndNonce(suite CipherSuite, epochSecret []byte) keyAndNonce {
	secretSize := suite.Constants().SecretSize
	keySize := suite.Constants().KeySize
	nonceSize := suite.Constants().NonceSize

	groupInfoSecret := suite.hkdfExpandLabel(epochSecret, "group info", []byte{}, secretSize)
	groupInfoKey := suite.hkdfExpandLabel(groupInfoSecret, "key", []byte{}, keySize)
	groupInfoNonce := suite.hkdfExpandLabel(groupInfoSecret, "nonce", []byte{}, nonceSize)

	return keyAndNonce{
		Key:   groupInfoKey,
		Nonce: groupInfoNonce,
	}
}

///
/// Key schedule epoch
///

type keyScheduleEpoch struct {
	Suite        CipherSuite
	GroupContext []byte `tls:"head=1"`

	EpochSecret       []byte `tls:"head=1"`
	SenderDataSecret  []byte `tls:"head=1"`
	SenderDataKey     []byte `tls:"head=1"`
	HandshakeSecret   []byte `tls:"head=1"`
	ApplicationSecret []byte `tls:"head=1"`
	ExporterSecret    []byte `tls:"head=1"`
	ConfirmationKey   []byte `tls:"head=1"`
	InitSecret        []byte `tls:"head=1"`

	HandshakeBaseKeys   *noFSBaseKeySource
	ApplicationBaseKeys *treeBaseKeySource

	HandshakeRatchets   map[LeafIndex]*hashRatchet `tls:"head=4"`
	ApplicationRatchets map[LeafIndex]*hashRatchet `tls:"head=4"`

	ApplicationKeys *groupKeySource `tls:"omit"`
	HandshakeKeys   *groupKeySource `tls:"omit"`
}

func newKeyScheduleEpoch(suite CipherSuite, size LeafCount, epochSecret, context []byte) keyScheduleEpoch {
	senderDataSecret := suite.deriveSecret(epochSecret, "sender data", context)
	handshakeSecret := suite.deriveSecret(epochSecret, "handshake", context)
	applicationSecret := suite.deriveSecret(epochSecret, "app", context)
	exporterSecret := suite.deriveSecret(epochSecret, "exporter", context)
	confirmationKey := suite.deriveSecret(epochSecret, "confirm", context)
	initSecret := suite.deriveSecret(epochSecret, "init", context)

	senderDataKey := suite.hkdfExpandLabel(senderDataSecret, "sd key", []byte{}, suite.Constants().KeySize)
	handshakeBaseKeys := newNoFSBaseKeySource(suite, handshakeSecret)
	applicationBaseKeys := newTreeBaseKeySource(suite, size, applicationSecret)

	kse := keyScheduleEpoch{
		Suite:        suite,
		GroupContext: context,

		EpochSecret:       epochSecret,
		SenderDataSecret:  senderDataSecret,
		SenderDataKey:     senderDataKey,
		HandshakeSecret:   handshakeSecret,
		ApplicationSecret: applicationSecret,
		ExporterSecret:    exporterSecret,
		ConfirmationKey:   confirmationKey,
		InitSecret:        initSecret,

		HandshakeBaseKeys:   handshakeBaseKeys,
		ApplicationBaseKeys: applicationBaseKeys,

		HandshakeRatchets:   map[LeafIndex]*hashRatchet{},
		ApplicationRatchets: map[LeafIndex]*hashRatchet{},
	}

	kse.enableKeySources()
	return kse
}

// Wire up the key sources as logic on top of data owned by the epoch
func (kse *keyScheduleEpoch) enableKeySources() {
	kse.HandshakeKeys = &groupKeySource{kse.HandshakeBaseKeys, kse.HandshakeRatchets}
	kse.ApplicationKeys = &groupKeySource{kse.ApplicationBaseKeys, kse.ApplicationRatchets}
}

func (kse *keyScheduleEpoch) Next(size LeafCount, pskIn, commitSecret, context []byte) keyScheduleEpoch {
	psk := pskIn
	if len(psk) == 0 {
		psk = kse.Suite.zero()
	}

	earlySecret := kse.Suite.hkdfExtract(psk, kse.InitSecret)
	preEpochSecret := kse.Suite.deriveSecret(earlySecret, "derived", context)
	epochSecret := kse.Suite.hkdfExtract(commitSecret, preEpochSecret)
	return newKeyScheduleEpoch(kse.Suite, size, epochSecret, context)
}

func (kse *keyScheduleEpoch) Export(label string, context []byte, keyLength int) []byte {
	exporterBase := kse.Suite.deriveSecret(kse.ExporterSecret, label, kse.GroupContext)
	hctx := kse.Suite.Digest(context)
	return kse.Suite.hkdfExpandLabel(exporterBase, "exporter", hctx, keyLength)
}
