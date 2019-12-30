package mls

import (
	"fmt"
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
	Sender uint32
	Hash   []byte `tls:"head=1"`
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
	Updates []ProposalID
	Removes ProposalID
	Adds    ProposalID
	Ignored ProposalID
	Path    *DirectPath
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

type MLSPlainText struct {
	GroupID           []byte `tls:"head=1"`
	Epoch             Epoch
	Sender            uint32
	AuthenticatedData []byte `tls:"head=4"`
	Content           MLSPlaintextContent
	Signature         []byte `tls:"head=2"`
}

type MLSCipherText struct {
	GroupID             []byte `tls:"head=1"`
	Epoch               Epoch
	ContentType         uint8
	SenderDataNonce     []byte `tls:"head=1"`
	EncryptedSenderData []byte `tls:"head=1"`
	CipherText          []byte `tls:"head=4"`
}
