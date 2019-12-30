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

type ClientInitKey struct {
	SupportedVersion uint8
	CipherSuite      CipherSuite
	InitKey          HPKEPublicKey
	Credential       Credential
	Extensions       ExtensionList
	Signature        []byte `tls:"head=2"`
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
	Removed uint32
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

type CommitData struct {
	Commit       Commit
	Confirmation []byte `tls:"head=1"`
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
	Sender            uint32
	AuthenticatedData []byte `tls:"head=4"`
	Content           MLSPlaintextContent
	Signature         []byte `tls:"head=2"`
}

type MLSCiphertext struct {
	GroupID             []byte `tls:"head=1"`
	Epoch               Epoch
	ContentType         uint8
	SenderDataNonce     []byte `tls:"head=1"`
	EncryptedSenderData []byte `tls:"head=1"`
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

	ConfirmedTranscriptHash []byte `tls:"head=1"`
	InterimTranscriptHash   []byte `tls:"head=1"`
	Path                    *DirectPath
	Confirmation            []byte `tls:"head=1"`

	SignerIndex uint32
	Signature   []byte `tls:"head=2"`
}

func (gi GroupInfo) toBeSigned() []byte {
	s := NewWriteStream()
	err := s.Write(struct {
		GroupId                 []byte `tls:"head=1"`
		Epoch                   Epoch
		Tree                    *RatchetTree
		ConfirmedTranscriptHash []byte `tls:"head=1"`
		InterimTranscriptHash   []byte `tls:"head=1"`
		Path                    *DirectPath
		Confirmation            []byte `tls:"head=1"`
		SignerIndex             uint32
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

	if err != nil {
		panic(fmt.Errorf("mls.groupInfo: marshal err %v", err))
	}

	return s.Data()
}

func (gi GroupInfo) sign(index leafIndex, priv SignaturePrivateKey) {
	// verify that priv corresponds to tree[index]
	c := gi.Tree.GetCredential(index)
	if !bytes.Equal(c.PublicKey().Data, priv.PublicKey.Data) {
		panic(fmt.Errorf("mls.groupInfo: badkey for index"))
	}
	// sign toBeSigned() with priv -> SignerIndex, Signature
	gi.SignerIndex = uint32(index)
	gi.Signature = c.Scheme().Sign(priv, gi.toBeSigned())
}

func (gi GroupInfo) verify() bool {
	// get pub from tree[SignerIndex] and verify (toBeSigned(), Signature) with pub
	c := gi.Tree.GetCredential(leafIndex(gi.SignerIndex))
	return c.Scheme().Verify(c.PublicKey(), gi.toBeSigned(), gi.Signature)
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

func newWelcome(cs CipherSuite, initSecret []byte, groupInfo GroupInfo) *Welcome {
	pt, err := syntax.Marshal(groupInfo)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: GroupInfo marshal failure %v", err))
	}

	// generate the keyy to encrypt groupInfo
	kn := deriveGroupKeyAndNonce(cs, initSecret)
	aead, err := cs.newAEAD(kn.Key)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: error creating AEAD: %v", err))
	}
	ct := aead.Seal(nil, kn.Nonce, pt, []byte{})

	w := &Welcome{
		Version:            0,
		CipherSuite:        cs,
		EncryptedGroupInfo: ct,
		initSecret:         initSecret,
	}
	return w
}

func (w *Welcome) encrypt(cik ClientInitKey) {

	data, err := syntax.Marshal(cik)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: CIK marshal failure %v", err))
	}

	cikHash := w.CipherSuite.digest(data)

	kp := KeyPackage{
		InitSecret: w.initSecret,
	}

	pt, err := syntax.Marshal(kp)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: KeyPackage marshal failure %v", err))
	}

	// encrypt the group init secret to new members PublicKey
	ep, err := w.CipherSuite.hpke().Encrypt(cik.InitKey, []byte{}, pt)
	if err != nil {
		panic(fmt.Errorf("mls.welcome: encrpyting KeyPackage failure %v", err))
	}

	ekp := EncryptedKeyPackage{
		ClientInitKeyHash: cikHash,
		EncryptedPackage:  ep,
	}
	w.EncryptedKeyPackages = append(w.EncryptedKeyPackages, ekp)
}
