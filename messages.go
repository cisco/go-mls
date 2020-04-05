package mls

import (
	"fmt"
	"reflect"
	"time"

	"github.com/bifurcation/mint/syntax"
)

///
/// KeyPackage
///
type Signature struct {
	Data []byte `tls:"head=2"`
}

type ProtocolVersion uint8

const (
	ProtocolVersionMLS10 ProtocolVersion = 0x00
)

var (
	supportedVersions     = []ProtocolVersion{ProtocolVersionMLS10}
	supportedCipherSuites = []CipherSuite{
		X25519_AES128GCM_SHA256_Ed25519,
		P256_AES128GCM_SHA256_P256,
		P521_AES256GCM_SHA512_P521,
	}
	defaultLifetime = 30 * 24 * time.Hour
)

type KeyPackage struct {
	Version     ProtocolVersion
	CipherSuite CipherSuite
	InitKey     HPKEPublicKey
	Credential  Credential
	Extensions  ExtensionList
	Signature   Signature
	privateKey  *HPKEPrivateKey `tls:"omit"`
}

func (kp KeyPackage) Equals(other KeyPackage) bool {
	version := kp.Version == other.Version
	suite := kp.CipherSuite == other.CipherSuite
	initKey := reflect.DeepEqual(kp.InitKey, other.InitKey)
	credential := kp.Credential.Equals(other.Credential)
	extensions := reflect.DeepEqual(kp.Extensions, kp.Extensions)
	signature := reflect.DeepEqual(kp.Signature, other.Signature)
	return version && suite && initKey && credential && extensions && signature
}

func (kp KeyPackage) Clone() KeyPackage {
	return KeyPackage{
		Version:     kp.Version,
		CipherSuite: kp.CipherSuite,
		InitKey:     kp.InitKey,
		Credential:  kp.Credential,
		Extensions:  kp.Extensions,
		Signature:   kp.Signature,
		privateKey:  kp.privateKey,
	}
}

func (kp KeyPackage) PrivateKey() (HPKEPrivateKey, bool) {
	if kp.privateKey == nil {
		return HPKEPrivateKey{}, false
	}

	return *kp.privateKey, true
}

func (kp *KeyPackage) SetPrivateKey(priv HPKEPrivateKey) error {
	if !kp.InitKey.Equals(priv.PublicKey) {
		return fmt.Errorf("Incorrect private key for key package")
	}

	kp.privateKey = &priv
	kp.InitKey = priv.PublicKey
	return nil
}

func (kp *KeyPackage) RemovePrivateKey() {
	kp.privateKey = nil
}

func (kp KeyPackage) toBeSigned() ([]byte, error) {
	enc, err := syntax.Marshal(struct {
		Version     ProtocolVersion
		CipherSuite CipherSuite
		InitKey     HPKEPublicKey
		Credential  Credential
		Extensions  ExtensionList
	}{
		Version:     kp.Version,
		CipherSuite: kp.CipherSuite,
		InitKey:     kp.InitKey,
		Credential:  kp.Credential,
		Extensions:  kp.Extensions,
	})

	if err != nil {
		return nil, err
	}

	return enc, nil
}

func (kp *KeyPackage) UpdateInitKey() error {
	initPriv, err := kp.CipherSuite.hpke().Generate()
	if err != nil {
		return err
	}

	kp.privateKey = &initPriv
	kp.InitKey = initPriv.PublicKey
	return nil
}

func (kp *KeyPackage) SetExtensions(exts []ExtensionBody) error {
	for _, ext := range exts {
		err := kp.Extensions.Add(ext)
		if err != nil {
			return err
		}
	}

	return nil
}

func (kp *KeyPackage) Sign() error {
	priv := kp.Credential.privateKey
	if priv == nil {
		return fmt.Errorf("No private key available for signing")
	}

	tbs, err := kp.toBeSigned()
	if err != nil {
		return err
	}

	sig, err := kp.Credential.Scheme().Sign(priv, tbs)
	if err != nil {
		return err
	}

	kp.Signature = Signature{sig}
	return nil
}

func (kp KeyPackage) Verify() bool {
	// Check for required extensions, but do not verify contents
	var sve SupportedVersionsExtension
	var sce SupportedCipherSuitesExtension
	foundSV, _ := kp.Extensions.Find(&sve)
	foundSC, _ := kp.Extensions.Find(&sce)
	if !foundSV || !foundSC {
		return false
	}

	// Verify that the KeyPackage has not expired
	var expirationExt ExpirationExtension
	found, err := kp.Extensions.Find(&expirationExt)
	if !found || err != nil {
		return false
	}

	expiry := time.Unix(int64(expirationExt), 0)
	if time.Now().After(expiry) {
		return false
	}

	// Verify the signature
	scheme := kp.Credential.Scheme()
	if scheme != kp.CipherSuite.scheme() {
		return false
	}

	tbs, err := kp.toBeSigned()
	if err != nil {
		return false
	}

	return kp.Credential.Scheme().Verify(kp.Credential.PublicKey(), tbs, kp.Signature.Data)
}

func NewKeyPackage(suite CipherSuite, cred *Credential) (*KeyPackage, error) {
	initKey, err := suite.hpke().Generate()
	if err != nil {
		return nil, err
	}

	return NewKeyPackageWithInitKey(suite, initKey, cred)
}

func NewKeyPackageWithInitKey(suite CipherSuite, initKey HPKEPrivateKey, cred *Credential) (*KeyPackage, error) {
	kp := &KeyPackage{
		Version:     ProtocolVersionMLS10,
		CipherSuite: suite,
		InitKey:     initKey.PublicKey,
		Credential:  *cred,
		privateKey:  &initKey,
	}

	// Add required extensions
	err := kp.Extensions.Add(SupportedVersionsExtension{supportedVersions})
	if err != nil {
		return nil, err
	}

	err = kp.Extensions.Add(SupportedCipherSuitesExtension{supportedCipherSuites})
	if err != nil {
		return nil, err
	}

	expiry := time.Now().Add(defaultLifetime).Unix()
	err = kp.Extensions.Add(ExpirationExtension(expiry))
	if err != nil {
		return nil, err
	}

	// Sign
	err = kp.Sign()
	if err != nil {
		return nil, err
	}
	return kp, nil
}

///
/// Proposal
///
type ProposalType uint8

const (
	ProposalTypeInvalid ProposalType = 0
	ProposalTypeAdd     ProposalType = 1
	ProposalTypeUpdate  ProposalType = 2
	ProposalTypeRemove  ProposalType = 3
)

func (pt ProposalType) ValidForTLS() error {
	return validateEnum(pt, ProposalTypeAdd, ProposalTypeUpdate, ProposalTypeRemove)
}

type AddProposal struct {
	KeyPackage KeyPackage
}

type UpdateProposal struct {
	KeyPackage KeyPackage
}

type RemoveProposal struct {
	Removed LeafIndex
}

type Proposal struct {
	Add    *AddProposal
	Update *UpdateProposal
	Remove *RemoveProposal
}

func (p Proposal) Type() ProposalType {
	switch {
	case p.Add != nil:
		return ProposalTypeAdd
	case p.Update != nil:
		return ProposalTypeUpdate
	case p.Remove != nil:
		return ProposalTypeRemove
	default:
		panic("Malformed proposal")
	}
}

func (p Proposal) MarshalTLS() ([]byte, error) {
	s := NewWriteStream()
	proposalType := p.Type()
	err := s.Write(proposalType)
	if err != nil {
		return nil, fmt.Errorf("mls.proposal: Marshal failed for ProposalType: %v", err)
	}

	switch proposalType {
	case ProposalTypeAdd:
		err = s.Write(p.Add)
	case ProposalTypeUpdate:
		err = s.Write(p.Update)
	case ProposalTypeRemove:
		err = s.Write(p.Remove)
	default:
		return nil, fmt.Errorf("mls.proposal: ProposalType type not allowed: %v", err)
	}

	if err != nil {
		return nil, fmt.Errorf("mls.proposal: Marshal failed: %v", err)
	}

	return s.Data(), nil
}

func (p *Proposal) UnmarshalTLS(data []byte) (int, error) {
	s := NewReadStream(data)
	var proposalType ProposalType
	_, err := s.Read(&proposalType)
	if err != nil {
		return 0, fmt.Errorf("mls.proposal: Unmarshal failed for ProposalTpe")
	}

	switch proposalType {
	case ProposalTypeAdd:
		p.Add = new(AddProposal)
		_, err = s.Read(p.Add)
	case ProposalTypeUpdate:
		p.Update = new(UpdateProposal)
		_, err = s.Read(p.Update)
	case ProposalTypeRemove:
		p.Remove = new(RemoveProposal)
		_, err = s.Read(p.Remove)
	default:
		err = fmt.Errorf("mls.proposal: ProposalType type not allowed")
	}

	if err != nil {
		return 0, err
	}

	return s.Position(), nil
}

///
/// Commit
///
type ProposalID struct {
	Hash []byte `tls:"head=1"`
}

func (pid ProposalID) String() string {
	return fmt.Sprintf("%x", pid.Hash)
}

type DirectPathNode struct {
	PublicKey            HPKEPublicKey
	EncryptedPathSecrets []HPKECiphertext `tls:"head=2"`
}

type DirectPath struct {
	Nodes []DirectPathNode `tls:"head=2"`
}

func (p *DirectPath) addNode(n DirectPathNode) {
	p.Nodes = append(p.Nodes, n)
}

type Commit struct {
	Updates []ProposalID `tls:"head=2"`
	Removes []ProposalID `tls:"head=2"`
	Adds    []ProposalID `tls:"head=2"`

	KeyPackage KeyPackage
	Path       DirectPath
}

///
/// MLSPlaintext and MLSCiphertext
///
type Epoch uint64

type ContentType uint8

const (
	ContentTypeInvalid     ContentType = 0
	ContentTypeApplication ContentType = 1
	ContentTypeProposal    ContentType = 2
	ContentTypeCommit      ContentType = 3
)

func (ct ContentType) ValidForTLS() error {
	return validateEnum(ct, ContentTypeApplication, ContentTypeProposal, ContentTypeCommit)
}

type SenderType uint8

const (
	SenderTypeInvalid       SenderType = 0
	SenderTypeMember        SenderType = 1
	SenderTypePreconfigured SenderType = 2
	SenderTypeNewMember     SenderType = 3
)

func (st SenderType) ValidForTLS() error {
	return validateEnum(st, SenderTypeMember, SenderTypePreconfigured, SenderTypeNewMember)
}

type Sender struct {
	Type   SenderType
	Sender uint32
}

type ApplicationData struct {
	Data []byte `tls:"head=4"`
}

type Confirmation struct {
	Data []byte `tls:"head=1"`
}
type CommitData struct {
	Commit       Commit
	Confirmation Confirmation
}

type MLSPlaintextContent struct {
	Application *ApplicationData
	Proposal    *Proposal
	Commit      *CommitData
}

func (c MLSPlaintextContent) Type() ContentType {
	switch {
	case c.Application != nil:
		return ContentTypeApplication
	case c.Proposal != nil:
		return ContentTypeProposal
	case c.Commit != nil:
		return ContentTypeCommit
	default:
		panic("Malformed plaintext content")
	}
}

func (c MLSPlaintextContent) MarshalTLS() ([]byte, error) {
	s := NewWriteStream()
	contentType := c.Type()
	err := s.Write(contentType)
	if err != nil {
		return nil, err
	}

	switch contentType {
	case ContentTypeApplication:
		err = s.Write(c.Application)
	case ContentTypeProposal:
		err = s.Write(c.Proposal)
	case ContentTypeCommit:
		err = s.Write(c.Commit)
	default:
		return nil, fmt.Errorf("mls.mlsplaintext: ContentType type not allowed")
	}

	if err != nil {
		return nil, err
	}

	return s.Data(), nil
}

func (c *MLSPlaintextContent) UnmarshalTLS(data []byte) (int, error) {
	s := NewReadStream(data)
	var contentType ContentType
	_, err := s.Read(&contentType)
	if err != nil {
		return 0, err
	}

	switch contentType {
	case ContentTypeApplication:
		c.Application = new(ApplicationData)
		_, err = s.Read(c.Application)
	case ContentTypeProposal:
		c.Proposal = new(Proposal)
		_, err = s.Read(c.Proposal)
	case ContentTypeCommit:
		c.Commit = new(CommitData)
		_, err = s.Read(c.Commit)
	default:
		return 0, fmt.Errorf("mls.mlsplaintext: ContentType type not allowed")
	}

	if err != nil {
		return 0, err
	}

	return s.Position(), nil
}

type MLSPlaintext struct {
	GroupID           []byte `tls:"head=1"`
	Epoch             Epoch
	Sender            Sender
	AuthenticatedData []byte `tls:"head=4"`
	Content           MLSPlaintextContent
	Signature         Signature
}

func (pt MLSPlaintext) toBeSigned(ctx GroupContext) []byte {
	s := NewWriteStream()
	err := s.Write(ctx)
	if err != nil {
		panic(fmt.Errorf("mls.mlsplaintext: grpCtx marshal failure %v", err))
	}

	err = s.Write(struct {
		GroupID           []byte `tls:"head=1"`
		Epoch             Epoch
		Sender            Sender
		AuthenticatedData []byte `tls:"head=4"`
		Content           MLSPlaintextContent
	}{
		GroupID:           pt.GroupID,
		Epoch:             pt.Epoch,
		Sender:            pt.Sender,
		AuthenticatedData: pt.AuthenticatedData,
		Content:           pt.Content,
	})

	if err != nil {
		panic(fmt.Errorf("mls.mlsplaintext: marshal failure %v", err))
	}
	return s.Data()
}

func (pt *MLSPlaintext) sign(ctx GroupContext, priv SignaturePrivateKey, scheme SignatureScheme) {
	tbs := pt.toBeSigned(ctx)
	sig, err := scheme.Sign(&priv, tbs)
	if err != nil {
		panic(err)
	}

	pt.Signature = Signature{sig}
}

func (pt *MLSPlaintext) verify(ctx GroupContext, pub *SignaturePublicKey, scheme SignatureScheme) bool {
	tbs := pt.toBeSigned(ctx)
	return scheme.Verify(pub, tbs, pt.Signature.Data)
}

func (pt MLSPlaintext) commitContent() []byte {
	enc, err := syntax.Marshal(struct {
		GroupId     []byte `tls:"head=1"`
		Epoch       Epoch
		Sender      Sender
		Commit      Commit
		ContentType ContentType
	}{
		GroupId:     pt.GroupID,
		Epoch:       pt.Epoch,
		Sender:      pt.Sender,
		Commit:      pt.Content.Commit.Commit,
		ContentType: pt.Content.Type(),
	})

	if err != nil {
		return nil
	}

	return enc
}
func (pt MLSPlaintext) commitAuthData() ([]byte, error) {
	data := pt.Content.Commit
	s := NewWriteStream()
	err := s.WriteAll(data.Confirmation, pt.Signature)
	if err != nil {
		return nil, err
	}
	return s.Data(), nil
}

type MLSCiphertext struct {
	GroupID             []byte `tls:"head=1"`
	Epoch               Epoch
	ContentType         ContentType
	SenderDataNonce     []byte `tls:"head=1"`
	EncryptedSenderData []byte `tls:"head=1"`
	AuthenticatedData   []byte `tls:"head=4"`
	Ciphertext          []byte `tls:"head=4"`
}

///
/// GroupInfo
///

type GroupInfo struct {
	GroupID                 []byte `tls:"head=1"`
	Epoch                   Epoch
	Tree                    RatchetTree
	ConfirmedTranscriptHash []byte `tls:"head=1"`
	InterimTranscriptHash   []byte `tls:"head=1"`
	Extensions              ExtensionList
	Confirmation            []byte `tls:"head=1"`
	SignerIndex             LeafIndex
	Signature               []byte `tls:"head=2"`
}

func (gi GroupInfo) dump() {
	fmt.Printf("\n+++++ groupInfo +++++\n")
	fmt.Printf("\tGroupID %x, Epoch %x\n", gi.GroupID, gi.Epoch)
	gi.Tree.dump("Tree")
	fmt.Printf("ConfirmedTranscriptHash %x, InterimTranscriptHash %x\n",
		gi.ConfirmedTranscriptHash, gi.InterimTranscriptHash)
	fmt.Printf("\tConfirmation %x, SignerIndex %x\n", gi.Confirmation, gi.SignerIndex)
	fmt.Printf("\tSignature %x\n", gi.Signature)
	fmt.Printf("\n+++++ groupInfo +++++\n")
}

func (gi GroupInfo) toBeSigned() ([]byte, error) {
	return syntax.Marshal(struct {
		GroupID                 []byte `tls:"head=1"`
		Epoch                   Epoch
		Tree                    RatchetTree
		ConfirmedTranscriptHash []byte `tls:"head=1"`
		InterimTranscriptHash   []byte `tls:"head=1"`
		Confirmation            []byte `tls:"head=1"`
		SignerIndex             LeafIndex
	}{
		GroupID:                 gi.GroupID,
		Epoch:                   gi.Epoch,
		Tree:                    gi.Tree,
		ConfirmedTranscriptHash: gi.ConfirmedTranscriptHash,
		InterimTranscriptHash:   gi.InterimTranscriptHash,
		Confirmation:            gi.Confirmation,
		SignerIndex:             gi.SignerIndex,
	})
}

func (gi *GroupInfo) sign(index LeafIndex, priv *SignaturePrivateKey) error {
	// Verify that priv corresponds to tree[index]
	kp, ok := gi.Tree.KeyPackage(index)
	if !ok {
		return fmt.Errorf("mls.groupInfo: Attempt to sign from unoccupied leaf")
	}

	scheme := kp.CipherSuite.scheme()
	pub := kp.Credential.PublicKey()
	if !pub.Equals(priv.PublicKey) {
		return fmt.Errorf("mls.groupInfo: Incorrect private key for index")
	}

	// Marshal the contents
	gi.SignerIndex = index
	tbs, err := gi.toBeSigned()
	if err != nil {
		return err
	}

	// Sign toBeSigned() with priv -> SignerIndex, Signature
	sig, err := scheme.Sign(priv, tbs)
	if err != nil {
		return err
	}

	gi.Signature = sig
	return nil
}

func (gi GroupInfo) verify() error {
	// Get pub from tree[SignerIndex]
	kp, ok := gi.Tree.KeyPackage(gi.SignerIndex)
	if !ok {
		return fmt.Errorf("mls.groupInfo: Attempt to sign from unoccupied leaf")
	}

	scheme := kp.CipherSuite.scheme()
	pub := kp.Credential.PublicKey()

	// Marshal the contents of the GroupInfo
	tbs, err := gi.toBeSigned()
	if err != nil {
		return err
	}

	// Verify (toBeSigned(), Signature) with pub
	ver := scheme.Verify(pub, tbs, gi.Signature)
	if !ver {
		return fmt.Errorf("mls.groupInfo: Vefication failed")
	}

	return nil
}

///
/// GroupSecrets
///
type GroupSecrets struct {
	EpochSecret []byte `tls:"head=1"`
	PathSecret  []byte `tls:"head=1"`
}

///
/// EncryptedGroupSecrets
///
type EncryptedGroupSecrets struct {
	KeyPackageHash        []byte `tls:"head=1"`
	EncryptedGroupSecrets HPKECiphertext
}

///
/// Welcome
///

type Welcome struct {
	Version            ProtocolVersion
	CipherSuite        CipherSuite
	Secrets            []EncryptedGroupSecrets `tls:"head=4"`
	EncryptedGroupInfo []byte                  `tls:"head=4"`
	epochSecret        []byte                  `tls:"omit"`
}

// XXX(rlb): The pattern we follow here basically locks us into having empty
// AAD.  I suspect that eventually we're going to want to have the header to the
// message (version, cipher, encrypted key packages) as AAD.  We should consider
// refactoring so that the API flows slightly differently:
//
// * newWelcome() - caches initSecret and *unencrypted* GroupInfo
// * encrypt() for each member
// * finalize() - computes AAD and encrypts GroupInfo
//
// This will also probably require a helper method for decryption.
func newWelcome(cs CipherSuite, epochSecret []byte, groupInfo *GroupInfo) *Welcome {
	// Encrypt the GroupInfo
	pt, err := syntax.Marshal(groupInfo)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: GroupInfo marshal failure %v", err))
	}

	kn := groupInfoKeyAndNonce(cs, epochSecret)
	aead, err := cs.newAEAD(kn.Key)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: error creating AEAD: %v", err))
	}
	ct := aead.Seal(nil, kn.Nonce, pt, []byte{})

	// Assemble the Welcome
	return &Welcome{
		Version:            ProtocolVersionMLS10,
		CipherSuite:        cs,
		EncryptedGroupInfo: ct,
		epochSecret:        epochSecret,
	}
}

func (w *Welcome) EncryptTo(kp KeyPackage, pathSecret []byte) {
	// Compute the hash of the kp
	data, err := syntax.Marshal(kp)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: kp marshal failure %v", err))
	}

	kpHash := w.CipherSuite.digest(data)

	// Encrypt the group init secret to new member's public key
	gs := GroupSecrets{
		EpochSecret: w.epochSecret,
		PathSecret:  pathSecret,
	}

	pt, err := syntax.Marshal(gs)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: KeyPackage marshal failure %v", err))
	}

	egs, err := w.CipherSuite.hpke().Encrypt(kp.InitKey, []byte{}, pt)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: encrpyting KeyPackage failure %v", err))
	}

	// Assemble and append the key package
	ekp := EncryptedGroupSecrets{
		KeyPackageHash:        kpHash,
		EncryptedGroupSecrets: egs,
	}
	w.Secrets = append(w.Secrets, ekp)
}

func (w Welcome) Decrypt(suite CipherSuite, epochSecret []byte) (*GroupInfo, error) {
	tic := time.Now()

	gikn := groupInfoKeyAndNonce(suite, epochSecret)

	aead, err := suite.newAEAD(gikn.Key)
	if err != nil {
		return nil, fmt.Errorf("mls.state: error creating AEAD: %v", err)
	}

	data, err := aead.Open(nil, gikn.Nonce, w.EncryptedGroupInfo, []byte{})
	if err != nil {
		return nil, fmt.Errorf("mls.state: unable to decrypt groupInfo: %v", err)
	}

	toc := time.Now()
	elapsed := toc.Sub(tic)
	fmt.Printf("%18s:%18v\n", "Join(2.1.1)", elapsed)
	tic = time.Now()

	gi := new(GroupInfo)
	_, err = syntax.Unmarshal(data, gi)
	if err != nil {
		return nil, fmt.Errorf("mls.state: unable to unmarshal groupInfo: %v", err)
	}

	toc = time.Now()
	elapsed = toc.Sub(tic)
	fmt.Printf("%18s:%18v\n", "Join(2.1.2)", elapsed)
	tic = time.Now()

	gi.Tree.Suite = suite
	gi.Tree.SetHashAll()

	toc = time.Now()
	elapsed = toc.Sub(tic)
	fmt.Printf("%18s:%18v\n", "Join(2.1.3)", elapsed)
	tic = time.Now()

	if err = gi.verify(); err != nil {
		return nil, fmt.Errorf("mls.state: invalid groupInfo")
	}

	toc = time.Now()
	elapsed = toc.Sub(tic)
	fmt.Printf("%18s:%18v\n", "Join(2.1.4)", elapsed)

	gi.Tree.Suite = suite

	return gi, nil
}
