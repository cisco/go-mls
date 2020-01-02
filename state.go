package mls

import (
	"bytes"
	"fmt"
	"github.com/bifurcation/mint/syntax"
	"math/rand"
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

	// local state
	processedProposals map[string]bool
}

func newEmptyState(groupID []byte, cs CipherSuite, leafPriv HPKEPrivateKey, cred Credential) *State {
	tree := newRatchetTree(cs)
	tree.AddLeaf(0, &leafPriv.PublicKey, &cred)
	secret := make([]byte, cs.newDigest().Size())
	kse := newKeyScheduleEpoch(cs, 1, secret, []byte{})
	s := &State{
		CipherSuite:        cs,
		GroupID:            groupID,
		Epoch:              0,
		Tree:               *tree,
		Keys:               *kse,
		Index:              0,
		IdentityPriv:       *cred.privateKey,
		scheme:             cred.Scheme(),
		processedProposals: map[string]bool{},
		UpdateSecrets:      map[string][]byte{},
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
	commit := Commit{}
	joiners := []ClientInitKey{}

	for _, pt := range s.PendingProposals {
		pid := s.proposalId(pt)
		proposal := pt.Content.Proposal
		switch {
		case proposal.Add != nil:
			commit.Adds = append(commit.Adds, pid)
			joiners = append(joiners, proposal.Add.ClientInitKey)
		case proposal.Update != nil:
			commit.Updates = append(commit.Updates, pid)
		case proposal.Remove != nil:
			commit.Removes = append(commit.Removes, pid)
		}
	}

	fmt.Printf("mls.state: adds %v, updates %v, removes %v", len(commit.Adds),
		len(commit.Updates), len(commit.Removes))

	//next := reflect.DeepCop
	return nil, nil, nil, nil
}

/// Proposal processing helpers

func (s *State) apply(commit Commit) {
	s.applyProposals(commit.Updates)
	s.applyProposals(commit.Removes)
	s.applyProposals(commit.Adds)
	// tree truncate

}

func (s *State) applyAddProposal(add *AddProposal) {
	target := s.Tree.LeftmostFree()
	s.Tree.AddLeaf(target, &add.ClientInitKey.InitKey, &add.ClientInitKey.Credential)

}

func (s *State) applyRemoveProposal(remove *RemoveProposal) {
	s.Tree.BlankPath(leafIndex(remove.Removed), false)
}

func (s *State) applyUpdateProposal(target leafIndex, update *UpdateProposal) {
	s.Tree.BlankPath(target, false)
	s.Tree.MergePublic(target, &update.LeafKey)
}

func (s *State) applyUpdateSecret(target leafIndex, secret []byte) {
	s.Tree.BlankPath(target, false)
	s.Tree.Merge(target, secret)
}

func (s *State) applyProposals(ids []ProposalID) {
	for _, id := range ids {
		pt, ok := s.findProposal(id)
		if !ok {
			panic("mls.state: commit of unknown proposal")
		}
		proposal := pt.Content.Proposal
		switch {
		case proposal.Add != nil:
			s.applyAddProposal(proposal.Add)
		case proposal.Update != nil:
			if pt.Sender != s.Index {
				// apply update from the given member
				s.applyUpdateProposal(pt.Sender, proposal.Update)
			}
			// handle self-update commit
			if len(s.UpdateSecrets[id.String()]) == 0 {
				panic("mls.state: self-update with no cached secret")
			}
			s.applyUpdateSecret(pt.Sender, s.UpdateSecrets[id.String()])
		case proposal.Remove != nil:
			s.applyRemoveProposal(proposal.Remove)
		default:
			panic("mls.state: invalid proposal type")
		}
	}
}

func (s State) findProposal(id ProposalID) (MLSPlaintext, bool) {
	for _, pt := range s.PendingProposals {
		otherPid := s.proposalId(pt)
		if bytes.Equal(otherPid.Hash, id.Hash) {
			s.processedProposals[id.String()] = true
			return pt, true
		}
	}
	// we can return may be reference
	// regardless, the call has to do a check before
	// using the returned value
	return MLSPlaintext{}, false
}

func (s State) proposalId(plaintext MLSPlaintext) ProposalID {
	enc, err := syntax.Marshal(plaintext)
	if err != nil {
		panic(fmt.Errorf("mls.state: mlsPlainText marshal failure %v", err))

	}
	return ProposalID{
		Hash: s.CipherSuite.digest(enc),
	}
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
		Sender:  s.Index,
		Content: MLSPlaintextContent{
			Proposal: &p,
		},
	}

	pt.sign(s.groupContext(), s.IdentityPriv, s.scheme)
	return pt
}

func (s *State) handle(pt *MLSPlaintext) (*State, error) {
	// TODO
	return nil, nil
}

///// protect/unprotect and helpers

func (s *State) encrypt(pt *MLSPlaintext) *MLSCiphertext {
	var generation uint32
	var keys keyAndNonce
	switch pt.Content.Type() {
	case ContentTypeApplication:
		generation, keys = s.Keys.ApplicationKeys.Next(s.Index)
	case ContentTypeProposal, ContentTypeCommit:
		generation, keys = s.Keys.HandshakeKeys.Next(s.Index)
	default:
		panic("mls.state: encrypt unknown content type")
	}

	stream := NewWriteStream()
	// skipping error checks since we are trying plain integers
	_ = stream.Write(s.Index)
	_ = stream.Write(generation)
	senderData := stream.Data()
	senderDataNonce := make([]byte, s.CipherSuite.constants().NonceSize)
	rand.Read(senderDataNonce)
	senderDataAADVal := senderDataAAD(s.GroupID, s.Epoch, pt.Content.Type(), senderDataNonce)

	sdAead, _ := s.CipherSuite.newAEAD(keys.Key)
	sdCt := sdAead.Seal(nil, senderDataNonce, senderData, senderDataAADVal)

	// content data
	content, err := syntax.Marshal(pt)
	if err != nil {
		fmt.Printf("mls.state: mlsPlaintext marshal failure %v", err)
		return nil
	}
	aad := contentAAD(s.GroupID, s.Epoch, pt.Content.Type(),
		pt.AuthenticatedData, senderDataNonce, sdCt)

	aead, _ := s.CipherSuite.newAEAD(keys.Key)
	contentCt := aead.Seal(nil, keys.Nonce, content, aad)

	// set up MLSCipherText
	ct := &MLSCiphertext{
		GroupID:             s.GroupID,
		Epoch:               s.Epoch,
		ContentType:         uint8(pt.Content.Type()),
		AuthenticatedData:   pt.AuthenticatedData,
		SenderDataNonce:     senderDataNonce,
		EncryptedSenderData: sdCt,
		Ciphertext:          contentCt,
	}
	return ct
}

func (s *State) decrypt(ct *MLSCiphertext) (*MLSPlaintext, error) {
	if !bytes.Equal(ct.GroupID, s.GroupID) {
		return nil, fmt.Errorf("mls.state: ciphertext not from this group")
	}

	if ct.Epoch != s.Epoch {
		return nil, fmt.Errorf("mls.state: ciphertext not from this epoch")
	}

	// handle sender data
	sdAAD := senderDataAAD(ct.GroupID, ct.Epoch, ContentType(ct.ContentType), ct.SenderDataNonce)
	sdAead, _ := s.CipherSuite.newAEAD(s.Keys.SenderDataKey)
	sd, err := sdAead.Open(nil, ct.SenderDataNonce, ct.EncryptedSenderData, sdAAD)
	if err != nil {
		return nil, fmt.Errorf("mls.state: senderData decryption failure %v", err)
	}

	// parse the senderData
	var sender leafIndex
	var generation uint32
	stream := NewReadStream(sd)
	_, err = stream.Read(&sender)
	if err == nil {
		_, err = stream.Read(&generation)
	}

	if err != nil {
		return nil, fmt.Errorf("mls.state: senderData unmarshal failure %v", err)
	}

	if !s.Tree.occupied(sender) {
		return nil, fmt.Errorf("mls.state: encryptionn from unoccupied leaf %v", sender)
	}

	var keys keyAndNonce
	contentType := ContentType(ct.ContentType)
	switch contentType {
	case ContentTypeApplication:
		keys, err = s.Keys.ApplicationKeys.Get(sender, generation)
		if err != nil {
			return nil, fmt.Errorf("mls.state: application keys extraction failed %v", err)
		}
		s.Keys.ApplicationKeys.Erase(sender, generation)
	case ContentTypeProposal, ContentTypeCommit:
		keys, err = s.Keys.HandshakeKeys.Get(sender, generation)
		if err != nil {
			return nil, fmt.Errorf("mls.state: handshake keys extraction failed %v", err)
		}
		s.Keys.HandshakeKeys.Erase(sender, generation)
	default:
		return nil, fmt.Errorf("mls.state: unsupported content type")
	}

	aad := contentAAD(ct.GroupID, ct.Epoch, ContentType(ct.ContentType),
		ct.AuthenticatedData, ct.SenderDataNonce, ct.EncryptedSenderData)

	aead, _ := s.CipherSuite.newAEAD(keys.Key)
	content, err := aead.Open(nil, keys.Nonce, ct.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("mls.state: content decryption failure %v", err)
	}

	pt := &MLSPlaintext{
		GroupID:           s.GroupID,
		Epoch:             s.Epoch,
		Sender:            sender,
		AuthenticatedData: ct.AuthenticatedData,
		Content: MLSPlaintextContent{
			Application: &ApplicationData{
				Data: content,
			},
		},
	}

	return pt, nil
}

func (s *State) protect(data []byte) *MLSCiphertext {
	pt := &MLSPlaintext{
		GroupID: s.GroupID,
		Epoch:   s.Epoch,
		Sender:  s.Index,
		Content: MLSPlaintextContent{
			Application: &ApplicationData{
				Data: data,
			},
		},
	}
	pt.sign(s.groupContext(), s.IdentityPriv, s.scheme)
	return s.encrypt(pt)
}

func (s *State) unprotect(ct *MLSCiphertext) ([]byte, error) {
	// TODO
	pt, err := s.decrypt(ct)
	if err != nil {
		return nil, err
	}

	sigPubKey := s.Tree.GetCredential(pt.Sender).PublicKey()
	if !pt.verify(s.groupContext(), sigPubKey, s.scheme) {
		return nil, fmt.Errorf("invalid message signature")
	}

	if pt.Content.Type() != ContentTypeApplication {
		return nil, fmt.Errorf("unprotect attempted on non-application message")
	}

	return pt.Content.Application.Data, nil
}

func senderDataAAD(gid []byte, epoch Epoch, contentType ContentType, nonce []byte) []byte {
	s := NewWriteStream()
	err := s.Write(struct {
		GroupId         []byte `tls:"head=1"`
		Epoch           Epoch
		ContentType     ContentType
		SenderDataNonce []byte `tls:"head=1"`
	}{
		GroupId:         gid,
		Epoch:           epoch,
		ContentType:     contentType,
		SenderDataNonce: nonce,
	})

	if err != nil {
		return nil
	}

	return s.Data()
}

func contentAAD(gid []byte, epoch Epoch,
	contentType ContentType, authenticatedData []byte,
	nonce []byte, encSenderData []byte) []byte {

	s := NewWriteStream()
	err := s.Write(struct {
		GroupId             []byte `tls:"head=1"`
		Epoch               Epoch
		ContentType         ContentType
		AuthenticatedData   []byte `tls:"head=4"`
		SenderDataNonce     []byte `tls:"head=1"`
		EncryptedSenderData []byte `tls:"head=1"`
	}{
		GroupId:             gid,
		Epoch:               epoch,
		ContentType:         contentType,
		AuthenticatedData:   authenticatedData,
		SenderDataNonce:     nonce,
		EncryptedSenderData: encSenderData,
	})

	if err != nil {
		return nil
	}
	return s.Data()
}
