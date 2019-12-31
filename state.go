package mls

import (
	"bytes"
	"fmt"
	"github.com/bifurcation/mint/syntax"
)

///
/// GroupContext
///
type GroupContext struct {
	GroupID                 []byte `tls:"head=1"`
	Epoch                   Epoch
	TreeHash                []byte `tls:"head=1"`
	ConfirmedTranscriptHash []byte `tls:"head=1"`
}

///
/// State
///
// TODO: Make this serializable, including serializing private aspects of the tree
type State struct {
	// Shared confirmed state
	CipherSuite             CipherSuite
	GroupID                 []byte
	Epoch                   Epoch
	Tree                    RatchetTree
	ConfirmedTranscriptHash []byte
	InterimTranscriptHash   []byte

	// Shared secret state
	Keys keyScheduleEpoch

	// Per-participant state
	Index        leafIndex
	IdentityPriv SignaturePrivateKey
	scheme       SignatureScheme

	// Cache of proposals and update secrets
	// XXX: The map key for UpdateSecrets should actually be ProposalID, but that
	// struct can't be used as a map key because it's not comparable (because
	// slices are not comparable).  Instead, we use ProposalID.String()
	PendingProposals []MLSPlaintext
	UpdateSecrets    map[string][]byte
}

func newEmptyState(groupID []byte, cs CipherSuite, leafPriv HPKEPrivateKey, cred Credential) *State {
	tree := newRatchetTree(cs)
	tree.AddLeaf(0, &leafPriv.PublicKey, &cred)
	secret := make([]byte, cs.newDigest().Size())
	kse := newKeyScheduleEpoch(cs, 1, secret, []byte{})
	s := &State{
		CipherSuite:  cs,
		GroupID:      groupID,
		Epoch:        0,
		Tree:         *tree,
		Keys:         *kse,
		Index:        0,
		IdentityPriv: *cred.privateKey,
		scheme:       cred.Scheme(),
	}
	return s
}

func newJoinedState(ciks []ClientInitKey, welcome Welcome) (*State, error) {

	suite := welcome.CipherSuite

	s := new(State)
	s.CipherSuite = suite
	s.Tree = *newRatchetTree(suite)

	var kp KeyPackage
	var clientInitKey ClientInitKey
	var found = false

	// extract the keyPackage for initsecret
	for idx, cik := range ciks {
		data, err := syntax.Marshal(cik)
		if err != nil {
			return nil, fmt.Errorf("mls.state: cik %d marshal failure %v", idx, err)
		}
		cikhash := welcome.CipherSuite.digest(data)
		// parse the encryptedKeyPackage to find our right cik
		for _, ekp := range welcome.EncryptedKeyPackages {
			found = bytes.Equal(cikhash, ekp.ClientInitKeyHash)
			if !found {
				continue
			}

			if cik.CipherSuite != welcome.CipherSuite {
				return nil, fmt.Errorf("mls.state: ciphersuite mismatch")
			}

			if cik.privateKey == nil {
				return nil, fmt.Errorf("mls.state: no private key for init key")
			}

			if cik.Credential.privateKey == nil {
				return nil, fmt.Errorf("mls.state: no signing key for init key")
			}

			s.IdentityPriv = *cik.Credential.privateKey
			s.scheme = cik.Credential.Scheme()

			pt, err := suite.hpke().Decrypt(*cik.privateKey, []byte{}, ekp.EncryptedPackage)
			if err != nil {
				return nil, fmt.Errorf("mls.state: encKeyPkg decryption failure %v", err)
			}

			_, err = syntax.Unmarshal(pt, &kp)
			if err != nil {
				return nil, fmt.Errorf("mls.state: keyPkg unmarshal failure %v", err)
			}

			clientInitKey = cik
			break
		}

		if found {
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("mls.state: unable to decrypt welcome message")
	}

	// decrypt the groupInfo
	fe := newFirstEpoch(suite, kp.InitSecret)

	aead, err := suite.newAEAD(fe.GroupInfoKey)
	if err != nil {
		return nil, fmt.Errorf("mls.state: error creating AEAD: %v", err)
	}

	data, err := aead.Open(nil, fe.GroupInfoNonce, welcome.EncryptedGroupInfo, []byte{})
	if err != nil {
		return nil, fmt.Errorf("mls.state: unable to decrypt groupInfo: %v", err)
	}

	var gi GroupInfo
	_, err = syntax.Unmarshal(data, &gi)
	if err != nil {
		return nil, fmt.Errorf("mls.state: unable to unmarshal groupInfo: %v", err)
	}

	if err = gi.verify(); err != nil {
		return nil, fmt.Errorf("mls.state: invalid groupInfo")
	}

	// parse group info context
	s.Epoch = gi.Epoch
	s.GroupID = gi.GroupId
	s.Tree = *gi.Tree
	s.ConfirmedTranscriptHash = gi.ConfirmedTranscriptHash
	s.InterimTranscriptHash = gi.InterimTranscriptHash

	// add self to tree
	index, res := s.Tree.Find(clientInitKey)
	if !res {
		return nil, fmt.Errorf("mls.state: new joiner not in the tree")
	}
	s.Index = index
	s.Tree.Merge(s.Index, clientInitKey.privateKey.Data)

	decapCtx, err := syntax.Marshal(GroupContext{
		gi.GroupId,
		gi.Epoch,
		gi.Tree.RootHash(),
		gi.PriorConfirmedTranscriptHash,
	})
	updateSecret := s.Tree.Decap(leafIndex(gi.SignerIndex), decapCtx, gi.Path)

	encGrpCtx, err := syntax.Marshal(s.groupContext())
	if err != nil {
		return nil, fmt.Errorf("mls.state: groupCtx marshal failure %v", err)
	}

	s.Keys = *fe.Next(leafCount(s.Tree.size()), updateSecret, encGrpCtx)

	// confirmation verification
	hmac := suite.newHMAC(s.Keys.ConfirmationKey)
	hmac.Write(s.ConfirmedTranscriptHash)
	confirm := hmac.Sum(nil)
	if !bytes.Equal(confirm, gi.Confirmation) {
		return nil, fmt.Errorf("mls.state: confirmation failed to verif")
	}

	return s, nil
}

func negotiateWithPeer(groupID []byte, myCIKs, otherCIKs []ClientInitKey, commitSecret []byte) (*Welcome, *State, error) {
	// TODO

	var selected = false
	var mySelectedCik, otherSelectedCik ClientInitKey

	for _, mycik := range myCIKs {
		for _, ocik := range otherCIKs {
			if mycik.CipherSuite == ocik.CipherSuite {
				selected = true
				mySelectedCik = mycik
				otherSelectedCik = ocik
				break
			}
		}
		if selected {
			break
		}
	}

	if !selected {
		return nil, nil, fmt.Errorf("mls.state: negotiation failure")
	}

	//newEmptyState(groupID []byte, cs CipherSuite, leafPriv HPKEPrivateKey, cred Credential) *State {
	s := newEmptyState(groupID, mySelectedCik.CipherSuite, *mySelectedCik.privateKey, mySelectedCik.Credential)
	add := s.add(otherSelectedCik)
	s.handle(add)
	_, welcome, newState, err := s.commit(commitSecret)
	if err != nil {
		panic(fmt.Errorf("mls.state: commit failure"))
	}

	return welcome, newState, nil
}

func (s State) groupContext() GroupContext {
	return GroupContext{
		GroupID:                 s.GroupID,
		Epoch:                   s.Epoch,
		TreeHash:                s.Tree.RootHash(),
		ConfirmedTranscriptHash: s.ConfirmedTranscriptHash,
	}
}

func (s State) sign(p Proposal) *MLSPlaintext {
	pt := &MLSPlaintext{
		GroupID: s.GroupID,
		Epoch:   s.Epoch,
		Sender:  uint32(s.Index),
		Content: MLSPlaintextContent{
			Proposal: &p,
		},
	}

	pt.sign(s.groupContext(), s.IdentityPriv, s.scheme)
	return pt
}

func (s State) add(cik ClientInitKey) *MLSPlaintext {
	addProposal := Proposal{
		Add: &AddProposal{
			ClientInitKey: cik,
		},
	}
	return s.sign(addProposal)
}

func (s State) update(leafSecret []byte) *MLSPlaintext {
	key, err := s.CipherSuite.hpke().Derive(leafSecret)
	if err != nil {
		panic(fmt.Errorf("mls.state: deriving secret for update failure %v", err))
	}

	updateProposal := Proposal{
		Update: &UpdateProposal{
			LeafKey: key.PublicKey,
		},
	}

	return s.sign(updateProposal)
}

func (s *State) remove(removed leafIndex) *MLSPlaintext {
	removeProposal := Proposal{
		Remove: &RemoveProposal{
			Removed: uint32(removed),
		},
	}

	return s.sign(removeProposal)
}

func (s *State) commit(leafSecret []byte) (*MLSPlaintext, *Welcome, *State, error) {
	// TODO
	return nil, nil, nil, nil
}

func (s *State) handle(pt *MLSPlaintext) (*State, error) {
	// TODO
	return nil, nil
}

func (s *State) encrypt(pt *MLSPlaintext) *MLSCiphertext {
	// TODO
	return nil
}

func (s *State) decrypt(ct *MLSCiphertext) (*MLSPlaintext, error) {
	// TODO
	return nil, nil
}

func (s *State) protect(data []byte) *MLSCiphertext {
	// TODO
	return nil
}

func (s *State) unprotect(ct *MLSCiphertext) ([]byte, error) {
	// TODO
	return nil, nil
}
