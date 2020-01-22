package mls

import (
	"bytes"
	"fmt"
	"github.com/bifurcation/mint/syntax"
)

///
/// ClientInitKey
///
type ExtensionType uint16

type Extension struct {
	ExtensionType ExtensionType
	ExtensionData []byte `tls:"head=2"`
}

type ExtensionList struct {
	Extensions []Extension `tls:"head=2"`
}

type Signature struct {
	Data []byte `tls:"head=2"`
}

type SupportedVersion uint8

const (
	SupportedVersionMLS10 = 0
)

type ClientInitKey struct {
	SupportedVersion SupportedVersion
	CipherSuite      CipherSuite
	InitKey          HPKEPublicKey
	Credential       Credential
	//Extensions       ExtensionList
	Signature  Signature
	privateKey *HPKEPrivateKey `tls:"omit"`
}

func (cik ClientInitKey) toBeSigned() ([]byte, error) {
	enc, err := syntax.Marshal(struct {
		Version     SupportedVersion
		CipherSuite CipherSuite
		InitKey     HPKEPublicKey
		Credential  Credential
		//Extensions  ExtensionList
	}{
		Version:     cik.SupportedVersion,
		CipherSuite: cik.CipherSuite,
		InitKey:     cik.InitKey,
		Credential:  cik.Credential,
		//Extensions:  cik.Extensions,
	})

	if err != nil {
		return nil, err
	}

	return enc, nil
}

func (cik *ClientInitKey) sign() error {
	tbs, err := cik.toBeSigned()
	if err != nil {
		return err
	}

	sig, err := cik.Credential.Scheme().Sign(cik.Credential.privateKey, tbs)
	if err != nil {
		return err
	}

	cik.Signature = Signature{sig}
	return nil
}

func (cik ClientInitKey) verify() (bool, error) {
	tbs, err := cik.toBeSigned()
	if err != nil {
		return false, fmt.Errorf("mls.cik: verification marshal error %v", err)
	}

	return cik.Credential.Scheme().Verify(cik.Credential.PublicKey(), tbs, cik.Signature.Data), nil
}

func newClientInitKey(suite CipherSuite, cred *Credential) (*ClientInitKey, error) {
	priv, err := suite.hpke().Generate()
	if err != nil {
		return nil, fmt.Errorf("mls.cik: private key generation failure %v", err)
	}
	cik := new(ClientInitKey)
	cik.SupportedVersion = SupportedVersionMLS10
	cik.CipherSuite = suite
	cik.InitKey = priv.PublicKey
	cik.Credential = *cred
	cik.privateKey = &priv
	err = cik.sign()
	if err != nil {
		return nil, fmt.Errorf("mls.cik: sign marshal failure %v", err)
	}
	return cik, nil
}

///
/// Proposal
///
type ProposalType uint8

const (
	ProposalTypeInvalid = 0
	ProposalTypeAdd     = 1
	ProposalTypeUpdate  = 2
	ProposalTypeRemove  = 3
)

type AddProposal struct {
	ClientInitKey ClientInitKey
}

type UpdateProposal struct {
	LeafKey HPKEPublicKey
}

type RemoveProposal struct {
	Removed leafIndex
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

	var read int
	switch proposalType {
	case ProposalTypeAdd:
		p.Add = new(AddProposal)
		read, err = s.Read(p.Add)
	case ProposalTypeUpdate:
		p.Update = new(UpdateProposal)
		read, err = s.Read(p.Update)
	case ProposalTypeRemove:
		p.Remove = new(RemoveProposal)
		read, err = s.Read(p.Remove)
	default:
		err = fmt.Errorf("mls.proposal: ProposalType type not allowed")
	}

	if err != nil {
		return 0, err
	}

	return read, nil
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

func (p DirectPath) dump() {
	fmt.Printf("\n++++ DirectPath ++++\n")
	fmt.Printf("Num Nodes %d\n", len(p.Nodes))
	for _, n := range p.Nodes {
		fmt.Printf("\tPubKey %x\n", n.PublicKey)
		for _, e := range n.EncryptedPathSecrets {
			fmt.Printf("\t\tPathSecret %x\n", e)
		}
	}
	fmt.Printf("\n++++ DirectPath ++++\n")

}

func (p *DirectPath) addNode(n DirectPathNode) {
	p.Nodes = append(p.Nodes, n)
}

type Commit struct {
	Updates []ProposalID `tls:"head=2"`
	Removes []ProposalID `tls:"head=2"`
	Adds    []ProposalID `tls:"head=2"`
	Ignored []ProposalID `tls:"head=2"`
	Path    DirectPath
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
	Sender            leafIndex
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
		Sender            leafIndex
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
		Sender      leafIndex
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
	GroupId                      []byte `tls:"head=1"`
	Epoch                        Epoch
	Tree                         *RatchetTree
	PriorConfirmedTranscriptHash []byte `tls:"head=1"`
	ConfirmedTranscriptHash      []byte `tls:"head=1"`
	InterimTranscriptHash        []byte `tls:"head=1"`
	Path                         *DirectPath
	Confirmation                 []byte `tls:"head=1"`
	SignerIndex                  leafIndex
	Signature                    []byte `tls:"head=2"`
}

func (gi GroupInfo) dump() {
	fmt.Printf("\n+++++ groupInfo +++++\n")
	fmt.Printf("\tGroupId %x, Epoch %x\n", gi.GroupId, gi.Epoch)
	gi.Tree.Dump("Tree")
	fmt.Printf("\tPriorConfirmedTranscriptHash %x, ConfirmedTranscriptHash %x, InterimTranscriptHash %x\n",
		gi.PriorConfirmedTranscriptHash, gi.ConfirmedTranscriptHash, gi.InterimTranscriptHash)
	gi.Path.dump()
	fmt.Printf("\tConfirmation %x, SignerIndex %x\n", gi.Confirmation, gi.SignerIndex)
	fmt.Printf("\tSignature %x\n", gi.Signature)
	fmt.Printf("\n+++++ groupInfo +++++\n")
}

func (gi GroupInfo) toBeSigned() ([]byte, error) {
	return syntax.Marshal(struct {
		GroupId                 []byte `tls:"head=1"`
		Epoch                   Epoch
		Tree                    *RatchetTree
		ConfirmedTranscriptHash []byte `tls:"head=1"`
		InterimTranscriptHash   []byte `tls:"head=1"`
		Path                    *DirectPath
		Confirmation            []byte `tls:"head=1"`
		SignerIndex             leafIndex
	}{
		GroupId:                 gi.GroupId,
		Epoch:                   gi.Epoch,
		Tree:                    gi.Tree,
		ConfirmedTranscriptHash: gi.ConfirmedTranscriptHash,
		InterimTranscriptHash:   gi.InterimTranscriptHash,
		Path:                    gi.Path,
		Confirmation:            gi.Confirmation,
		SignerIndex:             gi.SignerIndex,
	})
}

func (gi *GroupInfo) sign(index leafIndex, priv *SignaturePrivateKey) error {
	// Verify that priv corresponds to tree[index]
	cred := gi.Tree.GetCredential(index)
	if !bytes.Equal(cred.PublicKey().Data, priv.PublicKey.Data) {
		return fmt.Errorf("mls.groupInfo: Incorrect private key for index")
	}

	// Marshal the contents
	gi.SignerIndex = index
	tbs, err := gi.toBeSigned()
	if err != nil {
		return err
	}

	// Sign toBeSigned() with priv -> SignerIndex, Signature
	sig, err := cred.Scheme().Sign(priv, tbs)
	if err != nil {
		return err
	}

	gi.Signature = sig
	return nil
}

func (gi GroupInfo) verify() error {
	// Get pub from tree[SignerIndex]
	cred := gi.Tree.GetCredential(gi.SignerIndex)

	// Marshal the contents of the GroupInfo
	tbs, err := gi.toBeSigned()
	if err != nil {
		return err
	}

	// Verify (toBeSigned(), Signature) with pub
	ver := cred.Scheme().Verify(cred.PublicKey(), tbs, gi.Signature)
	if !ver {
		return fmt.Errorf("mls.groupInfo: Vefication failed")
	}

	return nil
}

func newGroupInfo(gid []byte, epoch Epoch, tree RatchetTree, transriptHash []byte) *GroupInfo {
	gi := new(GroupInfo)
	gi.GroupId = gid
	gi.Epoch = epoch
	gi.Tree = tree.clone()
	gi.PriorConfirmedTranscriptHash = transriptHash
	return gi
}

///
/// KeyPackage
///
type KeyPackage struct {
	InitSecret []byte `tls:"head=1"`
}

///
/// EncryptedKeyPackage
///
type EncryptedKeyPackage struct {
	ClientInitKeyHash []byte `tls:"head=1"`
	EncryptedPackage  HPKECiphertext
}

///
/// Welcome
///

type Welcome struct {
	Version              uint8
	CipherSuite          CipherSuite
	EncryptedKeyPackages []EncryptedKeyPackage `tls:"head=4"`
	EncryptedGroupInfo   []byte                `tls:"head=4"`
	initSecret           []byte                `tls:"omit"`
}

func deriveGroupKeyAndNonce(suite CipherSuite, initSecret []byte) keyAndNonce {
	secretSize := suite.constants().SecretSize
	keySize := suite.constants().KeySize
	nonceSize := suite.constants().NonceSize

	groupInfoSecret := suite.hkdfExpandLabel(initSecret, "group info", []byte{}, secretSize)
	groupInfoKey := suite.hkdfExpandLabel(groupInfoSecret, "key", []byte{}, keySize)
	groupInfoNonce := suite.hkdfExpandLabel(groupInfoSecret, "nonce", []byte{}, nonceSize)

	return keyAndNonce{
		Key:   groupInfoKey,
		Nonce: groupInfoNonce,
	}
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
func newWelcome(cs CipherSuite, initSecret []byte, groupInfo *GroupInfo, joiners []ClientInitKey) *Welcome {
	// Encrypt the GroupInfo
	pt, err := syntax.Marshal(groupInfo)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: GroupInfo marshal failure %v", err))
	}

	kn := deriveGroupKeyAndNonce(cs, initSecret)
	aead, err := cs.newAEAD(kn.Key)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: error creating AEAD: %v", err))
	}
	ct := aead.Seal(nil, kn.Nonce, pt, []byte{})

	// Assemble the Welcome
	w := &Welcome{
		Version:            SupportedVersionMLS10,
		CipherSuite:        cs,
		EncryptedGroupInfo: ct,
		initSecret:         initSecret,
	}

	for _, joiner := range joiners {
		w.encrypt(joiner)
	}

	return w
}

func (w *Welcome) encrypt(cik ClientInitKey) {
	// Compute the hash of the CIK
	data, err := syntax.Marshal(cik)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: CIK marshal failure %v", err))
	}

	cikHash := w.CipherSuite.digest(data)

	// Encrypt the group init secret to new member's public key
	kp := KeyPackage{
		InitSecret: w.initSecret,
	}

	pt, err := syntax.Marshal(kp)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: KeyPackage marshal failure %v", err))
	}

	ep, err := w.CipherSuite.hpke().Encrypt(cik.InitKey, []byte{}, pt)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: encrpyting KeyPackage failure %v", err))
	}

	// Assemble and append the key package
	ekp := EncryptedKeyPackage{
		ClientInitKeyHash: cikHash,
		EncryptedPackage:  ep,
	}
	w.EncryptedKeyPackages = append(w.EncryptedKeyPackages, ekp)
}
