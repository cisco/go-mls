package mls

import (
	"fmt"
	"github.com/bifurcation/mint/syntax"
)

////// ClientInitKey

// enum {
//	invalid(0),
//	supported_versions(1),
//	supported_ciphersuites(2),
//	expiration(3),
//	(65535)
// } ExtensionType;

// struct {
//     ExtensionType extension_type;
//     opaque extension_data<0..2^16-1>;
// } Extension;
type ExtensionType uint16

type Extension struct {
	ExtensionType ExtensionType
	ExtensionData []byte `tls:"head=2"`
}

func (ext Extension) Marshal() ([]byte, error) {
	return syntax.Marshal(ext)
}

func (ext *Extension) Unmarshal(data []byte) (int, error) {
	return syntax.Unmarshal(data, ext)
}

type ExtensionList []Extension

type extensionListInner struct {
	List []Extension `tls:"head=2"`
}

func (el ExtensionList) Marshal() ([]byte, error) {
	return syntax.Marshal(extensionListInner{el})
}

func (el *ExtensionList) Unmarshal(data []byte) (int, error) {
	var list extensionListInner
	s := NewStreamReader()
	read, err := s.Read(data, &list)
	if err != nil {
		return 0, err
	}

	*el = list.List
	return read, nil
}

type HPKEPublicKey struct {
	Data []byte `tls:"head=2"`
}

type Signature struct {
	Data []byte `tls:"head=2"`
}

// struct {
//	ProtocolVersion supported_version;
//	opaque client_init_key_id<0..255>;
//	CipherSuite cipher_suite;
//	HPKEPublicKey init_key;
//	Credential credential;
//	Extension extensions<0..2^16-1>;
//	opaque signature<0..2^16-1>;
// } ClientInitKey;
type ClientInitKey struct {
	SupportedVersion uint8
	CipherSuite     CipherSuite
	InitKey         HPKEPublicKey
	Credential      Credential
	Extensions      ExtensionList
	Signature       Signature
}


type cikInner struct {
	SupportedVersion uint8
	CipherSuite     CipherSuite
	InitKey         HPKEPublicKey
	Credential      Credential
}

func (cik ClientInitKey) MarshalTLS() ([]byte, error) {
	s := NewStreamWriter()

	inner := cikInner {
		SupportedVersion: cik.SupportedVersion,
		CipherSuite:     cik.CipherSuite,
		InitKey:         cik.InitKey,
		Credential:      cik.Credential,
	}

	err := s.Write(inner)

	// Todo: revisit this to see if we can parse ExtensionList
	// using usual techniques. mint/syntax seems to have
	// similar issue too.
	enc, err := cik.Extensions.Marshal()
	err = s.Append(enc)

	err = s.Write(cik.Signature)

	if err != nil {
		fmt.Printf("err: %v", err)
		return nil, err
	}

	return s.Data(), nil
}

func (cik *ClientInitKey) UnmarshalTLS(data []byte) (int, error) {
	s := NewStreamReader()

	var inner cikInner
	read, err := s.Read(data, &inner)
	if err != nil {
		return 0, err
	}

	cik.SupportedVersion = inner.SupportedVersion
	cik.CipherSuite = inner.CipherSuite
	cik.InitKey = inner.InitKey
	cik.Credential = inner.Credential

	// Todo: revisit this to see if we can parse ExtensionList
	// using usual techniques. mint/syntax seems to have
	// similar issue too.
	var extList ExtensionList
	extLen, err := extList.Unmarshal(data[read:])
	if err != nil {
		return 0, err
	}
	cik.Extensions = extList

	s.ResetCursor(read + extLen)

	var sig Signature
	read, err = s.Read(data, &sig)
	cik.Signature = sig
	if err != nil {
		return 0, err
	}

	return read, nil
}

//// Proposal
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
	// this is a HPKEPublicKey (for this structure purposes it is opaque)
	LeafKey []byte `tls:"head=2"`
}

type RemoveProposal struct {
	Removed uint32
}

type Proposal struct {
	Type   ProposalType
	Add    *AddProposal
	Update *UpdateProposal
	Remove *RemoveProposal
}

func (p Proposal) MarshalTLS() ([]byte, error) {
	s := NewStreamWriter()
	err := s.Write(p.Type)
	if err != nil {
		return nil, fmt.Errorf("mls.proposal: Marshal failed for ProposalType: %v", err)
	}

	switch p.Type {
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
	s := NewStreamReader()
	_, err := s.Read(data, &p.Type)
	if err != nil {
		return 0, fmt.Errorf("mls.proposal: Unmarshal failed for ProposalTpe")
	}

	var read int
	switch p.Type {
	case ProposalTypeAdd:
		p.Add = new(AddProposal)
		read, err = s.Read(data, p.Add)
	case ProposalTypeUpdate:
		p.Update = new(UpdateProposal)
		read, err = s.Read(data, p.Update)
	case ProposalTypeRemove:
		p.Remove = new(RemoveProposal)
		read, err = s.Read(data, p.Remove)
	default:
		err = fmt.Errorf("mls.proposal: ProposalType type not allowed")
	}

	if err != nil {
		return 0, err
	}

	return read, nil
}

//// commit
type ProposalId struct {
	Sender uint32
	Hash   []byte `tls:"head=1"`
}

type HPKECipherText struct {
	KEMOutput  []byte `tls:"head=2"`
	CipherText []byte `tls:"head=2"`
}

// struct {
//		HPKEPublicKey public_key;
//		HPKECiphertext encrypted_path_secret<0..2^16-1>;
//  } DirectPathNode;
type RatchetTreeNode struct {
	PublicKey           HPKEPublicKey
	EncryptedPathSecret []HPKECipherText `tls:"head=2"`
}

type DirectPath struct {
	Nodes []RatchetTreeNode `tls:"head=2"`
}

type Commit struct {
	Updates []ProposalId
	Removes ProposalId
	Adds    ProposalId
	Ignored ProposalId
	Path    *DirectPath
}

///// MLSPlainText, MLSCipherText ...
type epoch uint32

const (
	ContentTypeInvalid     = 0
	ContentTypeApplication = 1
	ContentTypeProposal    = 2
	ContentTypeCommit      = 3
)

type ApplicationData struct {
	Data []byte `tls:"head=4"`
}

type ProposalList struct {
	Proposals []Proposal `tls:"head=4"`
}

type CommitData struct {
	Proposals    ProposalList
	Commit       Commit
	Confirmation []byte `tls:"head=1"`
}

//TODO:snk: refactor common elements between plain & cipher mls structs
// struct {
//     opaque group_id<0..255>;
//     uint32 epoch;
//     uint32 sender;
//     ContentType content_type;
//
//     select (MLSPlaintext.content_type) {
//         case handshake:
//             GroupOperation operation;
//             opaque confirmation<0..255>;
//
//         case application:
//             opaque application_data<0..2^32-1>;
//     }
//
//     opaque signature<0..2^16-1>;
// } MLSPlaintext;
type MLSPlainText struct {
	GroupId           []byte `tls:"head=1"`
	Epoch             epoch
	Sender            uint32
	ContentType       uint8
	AuthenticatedData []byte `tls:"head=4"`
	Application       *ApplicationData
	Proposal          *ProposalList
	Commit            *CommitData
	Signature         []byte `tls:"head=2"`
}

type RawMLSPlainTextBeg struct {
	GroupId           []byte `tls:"head=1"`
	Epoch             epoch
	Sender            uint32
	ContentType       uint8
	AuthenticatedData []byte `tls:"head=4"`
}

type RawMLSPlainTextTrail struct {
	Signature []byte `tls:"head=2"`
}

func (pt MLSPlainText) MarshalTLS() ([]byte, error) {
	// todo: move stream api to mint/syntax
	s := NewStreamWriter()
	err := s.Write(struct {
		GroupId           []byte `tls:"head=1"`
		Epoch             epoch
		Sender            uint32
		ContentType       uint8
		AuthenticatedData []byte `tls:"head=4"`
	}{
		GroupId:           pt.GroupId,
		Epoch:             pt.Epoch,
		Sender:            pt.Sender,
		ContentType:       pt.ContentType,
		AuthenticatedData: pt.AuthenticatedData,
	})

	if err != nil {
		return nil, fmt.Errorf("mls.mlsplaintext: Unable to marshal")
	}

	switch pt.ContentType {
	case ContentTypeApplication:
		err = s.Write(pt.Application)
	case ContentTypeProposal:
		err = s.Write(pt.Proposal)
	case ContentTypeCommit:
		err = s.Write(pt.Commit)
	default:
		return nil, fmt.Errorf("mls.mlsplaintext: ContentTpe type not allowed")
	}

	// write the signature
	err = s.Write(RawMLSPlainTextTrail{
		Signature: pt.Signature,
	})
	if err != nil {
		return nil, fmt.Errorf("mls.mlsplaintext: Marshal error")
	}
	return s.Data(), nil

}

func (pt *MLSPlainText) UnmarshalTLS(data []byte) (int, error) {
	s := NewStreamReader()
	plainTextBeg := new(RawMLSPlainTextBeg)
	read, err := s.Read(data, plainTextBeg)
	if err != nil {
		return 0, fmt.Errorf("mls:mlsplaintext: Unmarshal Error %v", err)
	}
	// populate the beg part
	pt.GroupId = plainTextBeg.GroupId
	pt.Epoch = plainTextBeg.Epoch
	pt.Sender = plainTextBeg.Sender
	pt.ContentType = plainTextBeg.ContentType
	pt.AuthenticatedData = plainTextBeg.AuthenticatedData

	switch pt.ContentType {
	case ContentTypeApplication:
		pt.Application = new(ApplicationData)
		read, err = s.Read(data, pt.Application)
	case ContentTypeProposal:
		pt.Proposal = new(ProposalList)
		read, err = s.Read(data, pt.Proposal)
	case ContentTypeCommit:
		pt.Commit = new(CommitData)
		read, err = s.Read(data, pt.Commit)
	default:
		err = fmt.Errorf("mls.mlsplaintext: ContentType type not allowed")
	}

	if err != nil {
		return 0, err
	}

	// read & populate the signature
	var sig RawMLSPlainTextTrail
	read, err = s.Read(data, &sig)
	if err != nil {
		return 0, fmt.Errorf("mls.mlsplaintext: Unmarshal failed for Signature %v", err)
	}
	pt.Signature = sig.Signature
	return read, nil
}

// struct {
//     opaque group_id<0..255>;
//     uint32 epoch;
//     ContentType content_type;
//     opaque sender_data_nonce<0..255>;
//     opaque encrypted_sender_data<0..255>;
//     opaque ciphertext<0..2^32-1>;
// } MLSCiphertext;
type MLSCipherText struct {
	GroupId             []byte `tls:"head=1"`
	Epoch               epoch
	ContentType         uint8
	SenderDataNonce     []byte `tls:"head=1"`
	EncryptedSenderData []byte `tls:"head=1"`
	CipherText          []byte `tls:"head=4"`
}