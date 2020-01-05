package mls

import (
	"bytes"
	"fmt"
	"github.com/bifurcation/mint/syntax"
	"math/rand"
	"reflect"
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

	// local state to identify proposals being procesesed
	// in the PendingProposals. Avoids linear loop to
	// remove entries from PendingProposals.
	processedProposals map[string]bool
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
		Keys:                    *kse,
		Index:                   0,
		IdentityPriv:            *cred.privateKey,
		scheme:                  cred.Scheme(),
		processedProposals:      map[string]bool{},
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
	s.processedProposals = map[string]bool{}

	// add self to tree
	index, res := s.Tree.Find(clientInitKey)
	if !res {
		return nil, fmt.Errorf("mls.state: new joiner not in the tree")
	}
	s.Index = index
	s.Tree.MergePrivate(s.Index, clientInitKey.privateKey)

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
	commit := Commit{}
	var joiners []ClientInitKey

	for _, pp := range s.PendingProposals {
		pid := s.proposalId(pp)
		if s.processedProposals[pid.String()] {
			fmt.Printf("mls.state: skipping processed proposal %v", pp)
			continue
		}

		proposal := pp.Content.Proposal
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

	// init new state to apply commit and ratchet forward
	next := s.clone()
	next.apply(commit)
	next.PendingProposals = nil

	// Start a GroupInfo with the prepared state
	prevInitSecret := s.Keys.InitSecret
	gi := new(GroupInfo)
	gi.GroupId = next.GroupID
	gi.Epoch = next.Epoch + 1
	gi.Tree = next.Tree.clone()
	gi.PriorConfirmedTranscriptHash = s.ConfirmedTranscriptHash

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

	// Create the Commit message and advance the transcripts / key schedule
	pt := next.ratchetAndSign(commit, updateSecret, s.groupContext())

	// Complete the GroupInfo and form the Welcome
	gi.ConfirmedTranscriptHash = next.ConfirmedTranscriptHash
	gi.InterimTranscriptHash = next.InterimTranscriptHash
	gi.Path = path
	gi.Confirmation = pt.Content.Commit.Confirmation
	err = gi.sign(s.Index, &s.IdentityPriv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mls.state: groupInfo sign failure %v", err)
	}

	welcome := newWelcome(s.CipherSuite, prevInitSecret, gi)
	for _, joiner := range joiners {
		welcome.encrypt(joiner)
	}

	return pt, welcome, next, nil
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
	s.Keys = *s.Keys.Next(leafCount(s.Tree.size()), secret, ctx)
}

func (s *State) ratchetAndSign(op Commit, updateSecret []byte, prevGrpCtx GroupContext) *MLSPlaintext {
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
	commit.Confirmation = hmac.Sum(nil)

	// sign the MLSPlainText and update state hashes
	// as a result of ratcheting.
	pt.sign(prevGrpCtx, s.IdentityPriv, s.scheme)

	digest := s.CipherSuite.newDigest()
	digest.Write(s.ConfirmedTranscriptHash)
	s.InterimTranscriptHash = digest.Sum(pt.commitAuthData())
	return pt
}

func (s *State) handle(pt *MLSPlaintext) (*State, error) {

	if !bytes.Equal(pt.GroupID, s.GroupID) {
		return nil, fmt.Errorf("mls.state: groupId mismatch")
	}

	if pt.Epoch != s.Epoch {
		return nil, fmt.Errorf("mls.state: epoch mismatch")
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
	next.apply(commitData.Commit)

	// apply the direct path
	ctx, err := syntax.Marshal(GroupContext{
		GroupID:                 next.GroupID,
		Epoch:                   next.Epoch,
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
	s.InterimTranscriptHash = digest.Sum(pt.commitAuthData())

	next.Epoch += 1
	next.updateEpochSecrets(updateSecret)

	// verify confirmation MAC
	if !next.verifyConfirmation(commitData.Confirmation) {
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
		ContentType:         uint8(pt.Content.Type()),
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
	cloned := new(State)
	cloned.CipherSuite = s.CipherSuite
	cloned.GroupID = append(s.GroupID[:0:0], s.GroupID...)
	cloned.Epoch = s.Epoch
	cloned.Tree = *s.Tree.clone()
	cloned.ConfirmedTranscriptHash = append(s.ConfirmedTranscriptHash[:0:0], s.ConfirmedTranscriptHash...)
	cloned.InterimTranscriptHash = append(s.InterimTranscriptHash[:0:0], s.InterimTranscriptHash...)
	cloned.Keys = s.Keys
	cloned.Index = s.Index
	cloned.IdentityPriv = s.IdentityPriv
	cloned.scheme = s.scheme
	if s.PendingProposals != nil {
		cloned.PendingProposals = append(s.PendingProposals[:0:0], s.PendingProposals...)
	}
	cloned.UpdateSecrets = s.UpdateSecrets
	cloned.processedProposals = s.processedProposals
	return cloned
}

// Compare the public aspects of two nodes
func (s State) Equals(o State) bool {

	if s.Epoch != o.Epoch && !bytes.Equal(s.GroupID, o.GroupID) && s.CipherSuite != o.CipherSuite {
		return false
	}

	return s.Tree.Equals(&o.Tree) && reflect.DeepEqual(s.Keys, o.Keys)
}
