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
		CipherSuite:             cs,
		GroupID:                 groupID,
		Epoch:                   0,
		Tree:                    *tree,
		Keys:                    kse,
		Index:                   0,
		IdentityPriv:            *cred.privateKey,
		scheme:                  cred.Scheme(),
		UpdateSecrets:           map[string][]byte{},
		ConfirmedTranscriptHash: []byte{},
		InterimTranscriptHash:   []byte{},
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
	var encKeyPackage EncryptedKeyPackage
	var found = false

	// extract the keyPackage for init secret
	for idx, cik := range ciks {
		data, err := syntax.Marshal(cik)
		if err != nil {
			return nil, fmt.Errorf("mls.state: cik %d marshal failure %v", idx, err)
		}
		cikhash := welcome.CipherSuite.digest(data)
		// parse the encryptedKeyPackage to find our right cik
		for _, ekp := range welcome.EncryptedKeyPackages {
			found = bytes.Equal(cikhash, ekp.ClientInitKeyHash)
			if found {
				clientInitKey = cik
				encKeyPackage = ekp
				break
			}
		}
		if found {
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("mls.state: unable to decrypt welcome message")
	}

	if clientInitKey.CipherSuite != welcome.CipherSuite {
		return nil, fmt.Errorf("mls.state: ciphersuite mismatch")
	}

	if clientInitKey.privateKey == nil {
		return nil, fmt.Errorf("mls.state: no private key for init key")
	}

	if clientInitKey.Credential.privateKey == nil {
		return nil, fmt.Errorf("mls.state: no signing key for init key")
	}

	s.IdentityPriv = *clientInitKey.Credential.privateKey
	s.scheme = clientInitKey.Credential.Scheme()

	pt, err := suite.hpke().Decrypt(*clientInitKey.privateKey, []byte{}, encKeyPackage.EncryptedPackage)
	if err != nil {
		return nil, fmt.Errorf("mls.state: encKeyPkg decryption failure %v", err)
	}

	_, err = syntax.Unmarshal(pt, &kp)
	if err != nil {
		return nil, fmt.Errorf("mls.state: keyPkg unmarshal failure %v", err)
	}

	// init the epoch with initSecret in the key package
	fe := newFirstEpoch(suite, kp.InitSecret)

	// decrypt the groupInfo
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
	s.Tree = *gi.Tree.clone()
	s.ConfirmedTranscriptHash = gi.ConfirmedTranscriptHash
	s.InterimTranscriptHash = gi.InterimTranscriptHash
	s.UpdateSecrets = map[string][]byte{}

	// add self to tree
	index, res := s.Tree.Find(clientInitKey)
	if !res {
		return nil, fmt.Errorf("mls.state: new joiner not in the tree")
	}
	s.Index = index
	err = s.Tree.MergePrivate(s.Index, clientInitKey.privateKey)
	if err != nil {
		return nil, err
	}

	decapCtx, err := syntax.Marshal(GroupContext{
		gi.GroupId,
		gi.Epoch,
		gi.Tree.RootHash(),
		gi.PriorConfirmedTranscriptHash,
	})

	updateSecret := s.Tree.Decap(gi.SignerIndex, decapCtx, gi.Path)
	if updateSecret == nil {
		return nil, fmt.Errorf("mls.state: decrypting root secret got nil value")
	}

	encGrpCtx, err := syntax.Marshal(s.groupContext())
	if err != nil {
		return nil, fmt.Errorf("mls.state: groupCtx marshal failure %v", err)
	}

	s.Keys = fe.Next(leafCount(s.Tree.size()), updateSecret, encGrpCtx)

	// confirmation verification
	hmac := suite.newHMAC(s.Keys.ConfirmationKey)
	hmac.Write(s.ConfirmedTranscriptHash)
	confirm := hmac.Sum(nil)
	if !bytes.Equal(confirm, gi.Confirmation) {
		return nil, fmt.Errorf("mls.state: confirmation failed to verify")
	}

	return s, nil
}

func negotiateWithPeer(groupID []byte, myCIKs, otherCIKs []ClientInitKey, commitSecret []byte) (*Welcome, *State, error) {
	var selected = false
	var mySelectedCik, otherSelectedCik ClientInitKey

	for _, mycik := range myCIKs {
		for _, ocik := range otherCIKs {
			if mycik.CipherSuite == ocik.CipherSuite && mycik.SupportedVersion == ocik.SupportedVersion {
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

	// init our state and add the negotiated peer's cik
	s := newEmptyState(groupID, mySelectedCik.CipherSuite, *mySelectedCik.privateKey, mySelectedCik.Credential)
	add := s.add(otherSelectedCik)
	// update tree state
	_, err := s.handle(add)
	if err != nil {
		return nil, nil, err
	}
	// commit the add and generate welcome to be sent to the peer
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

	pt := s.sign(updateProposal)
	pId := s.proposalId(*pt)
	s.UpdateSecrets[pId.String()] = leafSecret
	return pt
}

func (s *State) remove(removed leafIndex) *MLSPlaintext {
	removeProposal := Proposal{
		Remove: &RemoveProposal{
			Removed: removed,
		},
	}
	return s.sign(removeProposal)
}

func (s *State) commit(leafSecret []byte) (*MLSPlaintext, *Welcome, *State, error) {
	commit := Commit{}
	var joiners []ClientInitKey

	for _, pp := range s.PendingProposals {
		pid := s.proposalId(pp)
		proposal := pp.Content.Proposal
		switch proposal.Type() {
		case ProposalTypeAdd:
			commit.Adds = append(commit.Adds, pid)
			joiners = append(joiners, proposal.Add.ClientInitKey)
		case ProposalTypeUpdate:
			commit.Updates = append(commit.Updates, pid)
		case ProposalTypeRemove:
			commit.Removes = append(commit.Removes, pid)
		}
	}

	// init new state to apply commit and ratchet forward
	next := s.clone()
	err := next.apply(commit)
	if err != nil {
		return nil, nil, nil, err
	}

	// reset after commit the proposals
	next.PendingProposals = nil

	// Start a GroupInfo with the prepared state
	prevInitSecret := s.Keys.InitSecret
	gi := newGroupInfo(next.GroupID, next.Epoch+1, next.Tree, s.ConfirmedTranscriptHash)

	ctx, err := syntax.Marshal(GroupContext{
		GroupID:                 gi.GroupId,
		Epoch:                   gi.Epoch,
		TreeHash:                gi.Tree.RootHash(),
		ConfirmedTranscriptHash: gi.PriorConfirmedTranscriptHash,
	})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mls.state: grpCtx marshal failure %v", err)
	}

	// KEM new entropy to the group and the new joiners
	path, updateSecret := next.Tree.Encap(s.Index, ctx, leafSecret)
	commit.Path = *path

	// Create the Commit message and advance the transcripts / key schedule
	pt, err := next.ratchetAndSign(commit, updateSecret, s.groupContext())
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mls.state: racthet forward failed %v", err)
	}

	// Complete the GroupInfo and form the Welcome
	gi.ConfirmedTranscriptHash = next.ConfirmedTranscriptHash
	gi.InterimTranscriptHash = next.InterimTranscriptHash
	gi.Path = path
	gi.Confirmation = pt.Content.Commit.Confirmation.Data
	err = gi.sign(s.Index, &s.IdentityPriv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mls.state: groupInfo sign failure %v", err)
	}

	welcome := newWelcome(s.CipherSuite, prevInitSecret, gi, joiners)
	return pt, welcome, next, nil
}

/// Proposal processing helpers

func (s *State) apply(commit Commit) error {
	// state to identify proposals being processed
	// in the PendingProposals. Avoids linear loop to
	// remove entries from PendingProposals.
	var processedProposals = map[string]bool{}
	err := s.applyProposals(commit.Updates, processedProposals)
	if err != nil {
		return err
	}

	err = s.applyProposals(commit.Removes, processedProposals)
	if err != nil {
		return err
	}

	err = s.applyProposals(commit.Adds, processedProposals)
	if err != nil {
		return err
	}
	return nil
}

func (s *State) applyAddProposal(add *AddProposal) error {
	target := s.Tree.LeftmostFree()
	return s.Tree.AddLeaf(target, &add.ClientInitKey.InitKey, &add.ClientInitKey.Credential)
}

func (s *State) applyRemoveProposal(remove *RemoveProposal) error {
	return s.Tree.BlankPath(leafIndex(remove.Removed), false)
}

func (s *State) applyUpdateProposal(target leafIndex, update *UpdateProposal) error {
	err := s.Tree.BlankPath(target, false)
	if err != nil {
		return err
	}
	return s.Tree.MergePublic(target, &update.LeafKey)
}

func (s *State) applyUpdateSecret(target leafIndex, secret []byte) error {
	err := s.Tree.BlankPath(s.Index, false)
	if err != nil {
		return err
	}
	return s.Tree.Merge(s.Index, secret)
}

func (s *State) applyProposals(ids []ProposalID, processed map[string]bool) error {
	for _, id := range ids {
		pt, ok := s.findProposal(id)
		if !ok {
			return fmt.Errorf("mls.state: commit of unknow proposal type %v", id)
		}

		// we have processed this proposal already
		if processed[id.String()] {
			continue
		} else {
			processed[id.String()] = true
		}

		proposal := pt.Content.Proposal
		var err error
		switch proposal.Type() {
		case ProposalTypeAdd:
			err = s.applyAddProposal(proposal.Add)
			if err != nil {
				return err
			}
		case ProposalTypeUpdate:
			if pt.Sender != s.Index {
				// apply update from the given member
				err := s.applyUpdateProposal(pt.Sender, proposal.Update)
				if err != nil {
					return err
				}
				return nil
			}
			// handle self-update commit
			if len(s.UpdateSecrets[id.String()]) == 0 {
				return fmt.Errorf("mls.state: self-update with no cached secret")
			}
			err = s.applyUpdateSecret(pt.Sender, s.UpdateSecrets[id.String()])
			if err != nil {
				return err
			}
		case ProposalTypeRemove:
			err = s.applyRemoveProposal(proposal.Remove)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("mls.state: invalid proposal type")
		}
	}
	return nil
}

func (s State) findProposal(id ProposalID) (MLSPlaintext, bool) {
	for _, pt := range s.PendingProposals {
		otherPid := s.proposalId(pt)
		if bytes.Equal(otherPid.Hash, id.Hash) {
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

func (s *State) updateEpochSecrets(secret []byte) {
	ctx, err := syntax.Marshal(GroupContext{
		GroupID:                 s.GroupID,
		Epoch:                   s.Epoch,
		TreeHash:                s.Tree.RootHash(),
		ConfirmedTranscriptHash: s.ConfirmedTranscriptHash,
	})
	if err != nil {
		panic(fmt.Errorf("mls.state: update epoch secret failed %v", err))
	}
	s.Keys = s.Keys.Next(leafCount(s.Tree.size()), secret, ctx)
}

func (s *State) ratchetAndSign(op Commit, updateSecret []byte, prevGrpCtx GroupContext) (*MLSPlaintext, error) {
	pt := &MLSPlaintext{
		GroupID: s.GroupID,
		Epoch:   s.Epoch,
		Sender:  s.Index,
		Content: MLSPlaintextContent{
			Commit: &CommitData{
				Commit: op,
			},
		},
	}

	s.Epoch += 1
	// derive new key schedule based on the update secret
	s.updateEpochSecrets(updateSecret)

	// generate the confirmation based on the new keys
	commit := pt.Content.Commit
	hmac := s.CipherSuite.newHMAC(s.Keys.ConfirmationKey)
	hmac.Write(s.ConfirmedTranscriptHash)
	commit.Confirmation.Data = hmac.Sum(nil)

	// sign the MLSPlainText and update state hashes
	// as a result of ratcheting.
	pt.sign(prevGrpCtx, s.IdentityPriv, s.scheme)

	digest := s.CipherSuite.newDigest()
	digest.Write(s.ConfirmedTranscriptHash)
	authData, err := pt.commitAuthData()
	if err != nil {
		return nil, err
	}
	s.InterimTranscriptHash = digest.Sum(authData)
	return pt, nil
}

func (s *State) handle(pt *MLSPlaintext) (*State, error) {
	if !bytes.Equal(pt.GroupID, s.GroupID) {
		return nil, fmt.Errorf("mls.state: groupID mismatch %x != %x", pt.GroupID, s.GroupID)
	}

	if pt.Epoch != s.Epoch {
		return nil, fmt.Errorf("mls.state: epoch mismatch, have %v, got %v", s.Epoch, pt.Epoch)
	}

	sigPubKey := s.Tree.GetCredential(pt.Sender).PublicKey()
	if !pt.verify(s.groupContext(), sigPubKey, s.scheme) {
		return nil, fmt.Errorf("invalid handshake message signature")
	}

	// Proposals get queued, do not result in a state transition
	contentType := pt.Content.Type()
	if contentType == ContentTypeProposal {
		s.PendingProposals = append(s.PendingProposals, *pt)
		return nil, nil
	}

	if contentType != ContentTypeCommit {
		return nil, fmt.Errorf("mls.state: incorrect content type")
	}

	if pt.Sender == s.Index {
		return nil, fmt.Errorf("mls.state: handle own commits with caching")
	}

	// apply the commit
	commitData := pt.Content.Commit
	next := s.clone()
	err := next.apply(commitData.Commit)
	if err != nil {
		return nil, err
	}

	// apply the direct path
	ctx, err := syntax.Marshal(GroupContext{
		GroupID:                 next.GroupID,
		Epoch:                   next.Epoch + 1,
		TreeHash:                next.Tree.RootHash(),
		ConfirmedTranscriptHash: next.ConfirmedTranscriptHash,
	})
	if err != nil {
		return nil, fmt.Errorf("mls.state: failure to create context %v", err)
	}

	updateSecret := next.Tree.Decap(pt.Sender, ctx, &commitData.Commit.Path)

	// Update the transcripts and advance the key schedule
	digest := next.CipherSuite.newDigest()
	digest.Write(next.InterimTranscriptHash)
	s.ConfirmedTranscriptHash = digest.Sum(pt.commitContent())

	digest = next.CipherSuite.newDigest()
	digest.Write(next.ConfirmedTranscriptHash)
	authData, err := pt.commitAuthData()
	if err != nil {
		return nil, err
	}
	s.InterimTranscriptHash = digest.Sum(authData)

	next.Epoch += 1
	next.updateEpochSecrets(updateSecret)

	// verify confirmation MAC
	if !next.verifyConfirmation(commitData.Confirmation.Data) {
		return nil, fmt.Errorf("mls.state: confirmation failed to verify")
	}
	return next, nil
}

///// protect/unprotect and helpers

func (s State) verifyConfirmation(confirmation []byte) bool {
	// confirmation verification
	hmac := s.CipherSuite.newHMAC(s.Keys.ConfirmationKey)
	hmac.Write(s.ConfirmedTranscriptHash)
	confirm := hmac.Sum(nil)
	if !bytes.Equal(confirm, confirmation) {
		return false
	}
	return true
}

func (s *State) encrypt(pt *MLSPlaintext) (*MLSCiphertext, error) {
	var generation uint32
	var keys keyAndNonce
	switch pt.Content.Type() {
	case ContentTypeApplication:
		generation, keys = s.Keys.ApplicationKeys.Next(s.Index)
	case ContentTypeProposal, ContentTypeCommit:
		generation, keys = s.Keys.HandshakeKeys.Next(s.Index)
	default:
		return nil, fmt.Errorf("mls.state: encrypt unknown content type")
	}

	stream := NewWriteStream()
	// skipping error checks since we are trying plain integers
	err := stream.Write(s.Index)
	if err == nil {
		err = stream.Write(generation)
	}
	if err != nil {
		return nil, fmt.Errorf("mls.state: sender data marshal failure %v", err)
	}

	senderData := stream.Data()
	senderDataNonce := make([]byte, s.CipherSuite.constants().NonceSize)
	rand.Read(senderDataNonce)
	senderDataAADVal := senderDataAAD(s.GroupID, s.Epoch, pt.Content.Type(), senderDataNonce)
	sdAead, _ := s.CipherSuite.newAEAD(s.Keys.SenderDataKey)
	sdCt := sdAead.Seal(nil, senderDataNonce, senderData, senderDataAADVal)

	// content data
	stream = NewWriteStream()
	err = stream.Write(pt.Content)
	if err == nil {
		err = stream.Write(pt.Signature)
	}
	if err != nil {
		return nil, fmt.Errorf("mls.state: content marshal failure %v", err)
	}
	content := stream.Data()

	aad := contentAAD(s.GroupID, s.Epoch, pt.Content.Type(),
		pt.AuthenticatedData, senderDataNonce, sdCt)
	aead, _ := s.CipherSuite.newAEAD(keys.Key)
	contentCt := aead.Seal(nil, keys.Nonce, content, aad)

	// set up MLSCipherText
	ct := &MLSCiphertext{
		GroupID:             s.GroupID,
		Epoch:               s.Epoch,
		ContentType:         pt.Content.Type(),
		AuthenticatedData:   pt.AuthenticatedData,
		SenderDataNonce:     senderDataNonce,
		EncryptedSenderData: sdCt,
		Ciphertext:          contentCt,
	}

	return ct, nil
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

	// parse the Content and Signature
	stream = NewReadStream(content)
	var mlsContent MLSPlaintextContent
	var signature Signature
	_, err = stream.Read(&mlsContent)
	if err == nil {
		_, err = stream.Read(&signature)
	}
	if err != nil {
		return nil, fmt.Errorf("mls.state: content unmarshal failure %v", err)
	}
	_, _ = syntax.Unmarshal(content, &mlsContent)

	pt := &MLSPlaintext{
		GroupID:           s.GroupID,
		Epoch:             s.Epoch,
		Sender:            sender,
		AuthenticatedData: ct.AuthenticatedData,
		Content:           mlsContent,
		Signature:         signature,
	}
	return pt, nil
}

func (s *State) protect(data []byte) (*MLSCiphertext, error) {
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

func (s State) clone() *State {
	// Note: all the slice/map copy operations below on state are mere
	// reference copies.
	clone := &State{
		CipherSuite:             s.CipherSuite,
		GroupID:                 s.GroupID,
		Epoch:                   s.Epoch,
		Tree:                    *s.Tree.clone(),
		ConfirmedTranscriptHash: nil,
		InterimTranscriptHash:   make([]byte, len(s.InterimTranscriptHash)),
		Keys:                    s.Keys,
		Index:                   s.Index,
		IdentityPriv:            s.IdentityPriv,
		scheme:                  s.scheme,
		UpdateSecrets:           s.UpdateSecrets,
		PendingProposals:        make([]MLSPlaintext, len(s.PendingProposals)),
	}
	copy(clone.GroupID, s.GroupID)
	copy(clone.InterimTranscriptHash, s.InterimTranscriptHash)
	copy(clone.PendingProposals, s.PendingProposals)
	return clone
}

// Compare the public aspects of two nodes
func (s State) Equals(o State) bool {

	if s.Epoch != o.Epoch || !bytes.Equal(s.GroupID, o.GroupID) || s.CipherSuite != o.CipherSuite {
		return false
	}

	return s.Tree.Equals(&o.Tree)
}
