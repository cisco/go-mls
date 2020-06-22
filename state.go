package mls

import (
	"bytes"
	"fmt"
	"math/rand"
	"reflect"

	"github.com/cisco/go-tls-syntax"
)

///
/// GroupContext
///
type GroupContext struct {
	GroupID                 []byte `tls:"head=1"`
	Epoch                   Epoch
	TreeHash                []byte `tls:"head=1"`
	ConfirmedTranscriptHash []byte `tls:"head=1"`
	Extensions              ExtensionList
}

///
/// State
///

type ProposalRef uint64

func toRef(id ProposalID) ProposalRef {
	ref := uint64(0)
	for i := uint(0); i < 8; i++ {
		ref |= uint64(id.Hash[i]) << i
	}
	return ProposalRef(ref)
}

type updateSecrets struct {
	Secret       []byte               `tls:"head=1"`
	IdentityPriv *SignaturePrivateKey `tls:"optional"`
}

var supportedGroupExtensions = []ExtensionType{
	// TODO
}

type State struct {
	// Shared confirmed state
	CipherSuite             CipherSuite
	GroupID                 []byte `tls:"head=1"`
	Epoch                   Epoch
	Tree                    TreeKEMPublicKey
	ConfirmedTranscriptHash []byte `tls:"head=1"`
	InterimTranscriptHash   []byte `tls:"head=1"`
	Extensions              ExtensionList

	// Per-participant non-secret state
	Index            LeafIndex           `tls:"omit"`
	IdentityPriv     SignaturePrivateKey `tls:"omit"`
	TreePriv         TreeKEMPrivateKey   `tls:"omit"`
	Scheme           SignatureScheme     `tls:"omit"`
	PendingProposals []MLSPlaintext      `tls:"omit"`

	// Secret state
	PendingUpdates map[ProposalRef]updateSecrets `tls:"omit"`
	Keys           keyScheduleEpoch              `tls:"omit"`

	// Helpful information
	NewCredentials map[LeafIndex]bool
}

func NewEmptyState(groupID []byte, leafSecret []byte, sigPriv SignaturePrivateKey, kp KeyPackage) (*State, error) {
	return NewEmptyStateWithExtensions(groupID, leafSecret, sigPriv, kp, NewExtensionList())
}

func NewEmptyStateWithExtensions(groupID []byte, leafSecret []byte, sigPriv SignaturePrivateKey, kp KeyPackage, ext ExtensionList) (*State, error) {
	suite := kp.CipherSuite

	tree := NewTreeKEMPublicKey(suite)
	index := tree.AddLeaf(kp)

	treePriv := NewTreeKEMPrivateKey(suite, tree.Size(), index, leafSecret)

	// Verify that the creator supports the group's extensions
	for _, ext := range ext.Entries {
		if !kp.Extensions.Has(ext.ExtensionType) {
			return nil, fmt.Errorf("Unsupported extension type [%04x]", ext.ExtensionType)
		}
	}

	secret := make([]byte, suite.newDigest().Size())
	kse := newKeyScheduleEpoch(suite, 1, secret, []byte{})
	s := &State{
		CipherSuite:             kp.CipherSuite,
		GroupID:                 groupID,
		Epoch:                   0,
		Tree:                    *tree,
		Keys:                    kse,
		Index:                   0,
		IdentityPriv:            sigPriv,
		TreePriv:                *treePriv,
		Scheme:                  kp.Credential.Scheme(),
		PendingUpdates:          map[ProposalRef]updateSecrets{},
		ConfirmedTranscriptHash: []byte{},
		InterimTranscriptHash:   []byte{},
		Extensions:              ext,
		NewCredentials:          map[LeafIndex]bool{},
	}
	return s, nil
}

func NewStateFromWelcome(suite CipherSuite, epochSecret []byte, welcome Welcome) (*State, LeafIndex, []byte, error) {
	// Decrypt the GroupInfo
	gi, err := welcome.Decrypt(suite, epochSecret)
	if err != nil {
		return nil, 0, nil, err
	}

	// Construct the new state
	s := &State{
		CipherSuite:             suite,
		Epoch:                   gi.Epoch,
		Tree:                    gi.Tree.Clone(),
		GroupID:                 gi.GroupID,
		ConfirmedTranscriptHash: gi.ConfirmedTranscriptHash,
		InterimTranscriptHash:   gi.InterimTranscriptHash,
		Extensions:              gi.Extensions,
		PendingProposals:        []MLSPlaintext{},
		PendingUpdates:          map[ProposalRef]updateSecrets{},
		NewCredentials:          map[LeafIndex]bool{},
	}

	// At this point, every leaf in the tree is new
	// XXX(RLB) ... except our own
	for i := LeafIndex(0); i < LeafIndex(s.Tree.Size()); i++ {
		s.NewCredentials[i] = true
	}

	return s, gi.SignerIndex, gi.Confirmation, nil
}

func NewJoinedState(initSecret []byte, sigPrivs []SignaturePrivateKey, kps []KeyPackage, welcome Welcome) (*State, error) {
	var initPriv HPKEPrivateKey
	var sigPriv SignaturePrivateKey
	var keyPackage KeyPackage
	var encGroupSecrets EncryptedGroupSecrets
	var found = false
	suite := welcome.CipherSuite
	// extract the keyPackage for init secret
	for idx, kp := range kps {
		data, err := syntax.Marshal(kp)
		if err != nil {
			return nil, fmt.Errorf("mls.state: kp %d marshal failure %v", idx, err)
		}
		kphash := welcome.CipherSuite.Digest(data)
		// parse the encryptedKeyPackage to find our right kp
		for _, egs := range welcome.Secrets {
			found = bytes.Equal(kphash, egs.KeyPackageHash)
			if found {
				initPriv, err = kp.CipherSuite.hpke().Derive(initSecret)
				if err != nil {
					return nil, err
				}

				if !initPriv.PublicKey.Equals(kp.InitKey) {
					return nil, fmt.Errorf("Incorrect init secret")
				}

				sigPriv = sigPrivs[idx]
				keyPackage = kp
				encGroupSecrets = egs
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

	if keyPackage.CipherSuite != welcome.CipherSuite {
		return nil, fmt.Errorf("mls.state: ciphersuite mismatch")
	}

	pt, err := suite.hpke().Decrypt(initPriv, []byte{}, encGroupSecrets.EncryptedGroupSecrets)
	if err != nil {
		return nil, fmt.Errorf("mls.state: encKeyPkg decryption failure %v", err)
	}

	var groupSecrets GroupSecrets
	_, err = syntax.Unmarshal(pt, &groupSecrets)
	if err != nil {
		return nil, fmt.Errorf("mls.state: keyPkg unmarshal failure %v", err)
	}

	// Construct a new state based on the GroupInfo
	s, signerIndex, confirmation, err := NewStateFromWelcome(suite, groupSecrets.EpochSecret, welcome)
	if err != nil {
		return nil, err
	}

	s.IdentityPriv = sigPriv
	s.Scheme = keyPackage.Credential.Scheme()

	// Verify that the joiner supports the group's extensions
	for _, ext := range s.Extensions.Entries {
		if !keyPackage.Extensions.Has(ext.ExtensionType) {
			return nil, fmt.Errorf("Unsupported extension type [%04x]", ext.ExtensionType)
		}
	}

	// Construct TreeKEM private key from parts provided
	index, res := s.Tree.Find(keyPackage)
	if !res {
		return nil, fmt.Errorf("mls.state: new joiner not in the tree")
	}
	s.Index = index
	commonAncestor := ancestor(s.Index, signerIndex)

	var pathSecret []byte
	if groupSecrets.PathSecret != nil {
		pathSecret = groupSecrets.PathSecret.Data
	}

	treePriv := NewTreeKEMPrivateKeyForJoiner(s.CipherSuite, s.Index, s.Tree.Size(), initSecret, commonAncestor, pathSecret)
	s.TreePriv = *treePriv

	// Start up the key schedule
	encGrpCtx, err := syntax.Marshal(s.groupContext())
	if err != nil {
		return nil, fmt.Errorf("mls.state: groupCtx marshal failure %v", err)
	}

	s.Keys = newKeyScheduleEpoch(suite, LeafCount(s.Tree.Size()), groupSecrets.EpochSecret, encGrpCtx)

	// confirmation verification
	if !s.verifyConfirmation(confirmation) {
		return nil, fmt.Errorf("mls.state: confirmation failed to verify")
	}

	return s, nil
}

func (s State) Add(kp KeyPackage) (*MLSPlaintext, error) {
	// Verify that the new member supports the group's extensions
	for _, ext := range s.Extensions.Entries {
		if !kp.Extensions.Has(ext.ExtensionType) {
			return nil, fmt.Errorf("Unsupported extension type [%04x]", ext.ExtensionType)
		}
	}

	addProposal := Proposal{
		Add: &AddProposal{
			KeyPackage: kp,
		},
	}

	return s.sign(addProposal)
}

func (s State) Update(secret []byte, sigPriv *SignaturePrivateKey, kp KeyPackage) (*MLSPlaintext, error) {
	updateProposal := Proposal{
		Update: &UpdateProposal{
			KeyPackage: kp,
		},
	}

	pt, err := s.sign(updateProposal)
	if err != nil {
		return nil, err
	}
	ref := toRef(s.proposalID(*pt))
	s.PendingUpdates[ref] = updateSecrets{dup(secret), sigPriv}
	return pt, nil
}

func (s *State) Remove(removed LeafIndex) (*MLSPlaintext, error) {
	removeProposal := Proposal{
		Remove: &RemoveProposal{
			Removed: removed,
		},
	}
	pt, err := s.sign(removeProposal)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

func (s *State) Commit(leafSecret []byte) (*MLSPlaintext, *Welcome, *State, error) {
	// Construct and apply a commit message
	commit := Commit{}
	var joiners []KeyPackage

	for _, pp := range s.PendingProposals {
		pid := s.proposalID(pp)
		proposal := pp.Content.Proposal
		switch proposal.Type() {
		case ProposalTypeAdd:
			commit.Adds = append(commit.Adds, pid)
			joiners = append(joiners, proposal.Add.KeyPackage)
		case ProposalTypeUpdate:
			commit.Updates = append(commit.Updates, pid)
		case ProposalTypeRemove:
			commit.Removes = append(commit.Removes, pid)
		}
	}

	// init new state to apply commit and ratchet forward
	next := s.Clone()
	err := next.apply(commit)
	if err != nil {
		return nil, nil, nil, err
	}

	// reset after commit the proposals
	next.PendingProposals = nil

	// KEM new entropy to the new group if needed
	if commit.PathRequired() {
		ctx, err := syntax.Marshal(next.groupContext())
		if err != nil {
			return nil, nil, nil, err
		}

		treePriv, treePath, err := next.Tree.Encap(s.Index, ctx, leafSecret, next.IdentityPriv, nil)
		if err != nil {
			return nil, nil, nil, err
		}

		next.TreePriv = *treePriv
		commit.Path = treePath
	}

	// Create the Commit message and advance the transcripts / key schedule
	pt, err := next.ratchetAndSign(commit, next.TreePriv.UpdateSecret, s.groupContext(), s.IdentityPriv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mls.state: racthet forward failed %v", err)
	}

	// Complete the GroupInfo and form the Welcome
	gi := &GroupInfo{
		GroupID:                 next.GroupID,
		Epoch:                   next.Epoch,
		Tree:                    next.Tree,
		ConfirmedTranscriptHash: next.ConfirmedTranscriptHash,
		InterimTranscriptHash:   next.InterimTranscriptHash,
		Confirmation:            pt.Content.Commit.Confirmation.Data,
	}
	err = gi.sign(next.Index, &next.IdentityPriv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("mls.state: groupInfo sign failure %v", err)
	}

	welcome := newWelcome(s.CipherSuite, next.Keys.EpochSecret, gi)
	for _, kp := range joiners {
		leaf, ok := next.Tree.Find(kp)
		if !ok {
			return nil, nil, nil, fmt.Errorf("mls.state: New joiner not in tree")
		}

		_, pathSecret, ok := next.TreePriv.SharedPathSecret(leaf)
		welcome.EncryptTo(kp, pathSecret)
	}

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
	if add.KeyPackage.CipherSuite != s.CipherSuite {
		return fmt.Errorf("mls.state: new member kp does not use group ciphersuite")
	}

	if !add.KeyPackage.Verify() {
		return fmt.Errorf("mls.state: Invalid kp")
	}

	target := s.Tree.AddLeaf(add.KeyPackage)
	s.NewCredentials[target] = true
	return nil
}

func (s *State) applyRemoveProposal(remove *RemoveProposal) {
	s.Tree.BlankPath(LeafIndex(remove.Removed))
}

func (s *State) applyUpdateProposal(target LeafIndex, update *UpdateProposal) error {
	if update.KeyPackage.CipherSuite != s.CipherSuite {
		panic(fmt.Errorf("mls.state: update kp does not use group ciphersuite %v != %v", update.KeyPackage.CipherSuite, s.CipherSuite))
	}

	if !update.KeyPackage.Verify() {
		return fmt.Errorf("mls.state: Invalid kp")
	}

	currKP, ok := s.Tree.KeyPackage(target)
	if !ok {
		return fmt.Errorf("mls.state: Attempt to update an empty leaf")
	}

	if !update.KeyPackage.Credential.Equals(currKP.Credential) {
		s.NewCredentials[target] = true
	}

	s.Tree.UpdateLeaf(target, update.KeyPackage)
	return nil
}

func (s *State) applyProposals(ids []ProposalID, processed map[string]bool) error {
	for _, id := range ids {
		pt, ok := s.findProposal(id)
		if !ok {
			return fmt.Errorf("mls.state: commit of unknown proposal %s", id)
		}

		// we have processed this proposal already
		if processed[id.String()] {
			continue
		} else {
			processed[id.String()] = true
		}

		proposal := pt.Content.Proposal
		switch proposal.Type() {
		case ProposalTypeAdd:
			err := s.applyAddProposal(proposal.Add)
			if err != nil {
				return err
			}
		case ProposalTypeUpdate:
			if pt.Sender.Type != SenderTypeMember {
				return fmt.Errorf("mls.state: update from non-member")
			}

			senderIndex := LeafIndex(pt.Sender.Sender)
			err := s.applyUpdateProposal(senderIndex, proposal.Update)
			if err != nil {
				return err
			}

			if senderIndex == s.Index {
				secrets, ok := s.PendingUpdates[toRef(id)]
				if !ok {
					return fmt.Errorf("mls.state: self-update with no cached secret")
				}

				s.TreePriv.SetLeafSecret(secrets.Secret)
				if secrets.IdentityPriv != nil {
					s.IdentityPriv = *secrets.IdentityPriv
				}
			}

		case ProposalTypeRemove:
			s.applyRemoveProposal(proposal.Remove)

		default:
			return fmt.Errorf("mls.state: invalid proposal type")
		}
	}
	return nil
}

func (s State) findProposal(id ProposalID) (MLSPlaintext, bool) {
	for _, pt := range s.PendingProposals {
		otherPid := s.proposalID(pt)
		if bytes.Equal(otherPid.Hash, id.Hash) {
			return pt, true
		}
	}
	// we can return may be reference
	// regardless, the call has to do a check before
	// using the returned value
	return MLSPlaintext{}, false
}

func (s State) proposalID(plaintext MLSPlaintext) ProposalID {
	enc, err := syntax.Marshal(plaintext)
	if err != nil {
		panic(fmt.Errorf("mls.state: mlsPlainText marshal failure %v", err))

	}
	return ProposalID{
		Hash: s.CipherSuite.Digest(enc),
	}
}

func (s State) groupContext() GroupContext {
	return GroupContext{
		GroupID:                 s.GroupID,
		Epoch:                   s.Epoch,
		TreeHash:                s.Tree.RootHash(),
		ConfirmedTranscriptHash: s.ConfirmedTranscriptHash,
		Extensions:              s.Extensions,
	}
}

func (s State) sign(p Proposal) (*MLSPlaintext, error) {
	pt := &MLSPlaintext{
		GroupID: s.GroupID,
		Epoch:   s.Epoch,
		Sender:  Sender{SenderTypeMember, uint32(s.Index)},
		Content: MLSPlaintextContent{
			Proposal: &p,
		},
	}

	err := pt.sign(s.groupContext(), s.IdentityPriv, s.Scheme)
	if err != nil {
		return nil, err
	}
	return pt, nil
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

	// TODO(RLB) Provide an API to provide PSKs
	s.Keys = s.Keys.Next(LeafCount(s.Tree.Size()), nil, secret, ctx)
}

func (s *State) ratchetAndSign(op Commit, commitSecret []byte, prevGrpCtx GroupContext, sigPriv SignaturePrivateKey) (*MLSPlaintext, error) {
	pt := &MLSPlaintext{
		GroupID: s.GroupID,
		Epoch:   s.Epoch,
		Sender:  Sender{SenderTypeMember, uint32(s.Index)},
		Content: MLSPlaintextContent{
			Commit: &CommitData{
				Commit: op,
			},
		},
	}

	// Update the Confirmed Transcript Hash
	digest := s.CipherSuite.newDigest()
	digest.Write(s.InterimTranscriptHash)
	digest.Write(pt.commitContent())
	s.ConfirmedTranscriptHash = digest.Sum(nil)

	// Advance the key schedule
	s.Epoch += 1
	s.updateEpochSecrets(commitSecret)

	// generate the confirmation based on the new keys
	commit := pt.Content.Commit
	hmac := s.CipherSuite.NewHMAC(s.Keys.ConfirmationKey)
	hmac.Write(s.ConfirmedTranscriptHash)
	commit.Confirmation.Data = hmac.Sum(nil)

	// sign the MLSPlainText and update state hashes
	// as a result of ratcheting.
	err := pt.sign(prevGrpCtx, sigPriv, s.Scheme)
	if err != nil {
		return nil, err
	}

	authData, err := pt.commitAuthData()
	if err != nil {
		return nil, err
	}

	digest = s.CipherSuite.newDigest()
	digest.Write(s.ConfirmedTranscriptHash)
	digest.Write(authData)
	s.InterimTranscriptHash = digest.Sum(nil)

	return pt, nil
}

func (s State) signerPublicKey(sender Sender) (*SignaturePublicKey, error) {
	switch sender.Type {
	case SenderTypeMember:
		kp, ok := s.Tree.KeyPackage(LeafIndex(sender.Sender))
		if !ok {
			return nil, fmt.Errorf("mls.state: Received from blank leaf")
		}

		return kp.Credential.PublicKey(), nil

	default:
		// TODO(RLB): Support add sent by new member
		// TODO(RLB): Support add/remove signed by preconfigured key
		return nil, fmt.Errorf("mls.state: Unsupported sender type")
	}
}

func (s *State) Handle(pt *MLSPlaintext) (*State, error) {
	if !bytes.Equal(pt.GroupID, s.GroupID) {
		return nil, fmt.Errorf("mls.state: groupId mismatch")
	}

	if pt.Epoch != s.Epoch {
		return nil, fmt.Errorf("mls.state: epoch mismatch, have %v, got %v", s.Epoch, pt.Epoch)
	}

	sigPubKey, err := s.signerPublicKey(pt.Sender)
	if err != nil {
		return nil, err
	}

	if !pt.verify(s.groupContext(), sigPubKey, s.Scheme) {
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
	} else if pt.Sender.Type != SenderTypeMember {
		return nil, fmt.Errorf("mls.state: commit from non-member")
	}

	if LeafIndex(pt.Sender.Sender) == s.Index {
		return nil, fmt.Errorf("mls.state: handle own commits with caching")
	}

	// apply the commit and discard any remaining pending proposals
	senderIndex := LeafIndex(pt.Sender.Sender)
	commitData := pt.Content.Commit
	next := s.Clone()
	err = next.apply(commitData.Commit)
	if err != nil {
		return nil, err
	}

	next.PendingProposals = next.PendingProposals[:0]

	// apply the direct path, if provided
	commitSecret := s.CipherSuite.zero()
	if commitData.Commit.Path != nil {
		ctx, err := syntax.Marshal(GroupContext{
			GroupID:                 next.GroupID,
			Epoch:                   next.Epoch,
			TreeHash:                next.Tree.RootHash(),
			ConfirmedTranscriptHash: next.ConfirmedTranscriptHash,
		})
		if err != nil {
			return nil, fmt.Errorf("mls.state: failure to create context %v", err)
		}

		err = next.TreePriv.Decap(senderIndex, next.Tree, ctx, *commitData.Commit.Path)
		if err != nil {
			return nil, err
		}

		commitSecret = next.TreePriv.UpdateSecret

		err = next.Tree.Merge(senderIndex, *commitData.Commit.Path)
		if err != nil {
			return nil, err
		}
	}

	// Update the confirmed transcript hash
	digest := next.CipherSuite.newDigest()
	digest.Write(next.InterimTranscriptHash)
	digest.Write(pt.commitContent())
	next.ConfirmedTranscriptHash = digest.Sum(nil)

	// Advance the key schedule
	next.Epoch += 1
	next.updateEpochSecrets(commitSecret)

	// Verify confirmation MAC
	if !next.verifyConfirmation(commitData.Confirmation.Data) {
		return nil, fmt.Errorf("mls.state: confirmation failed to verify")
	}

	authData, err := pt.commitAuthData()
	if err != nil {
		return nil, err
	}

	// Update the interim transcript hash
	digest = next.CipherSuite.newDigest()
	digest.Write(next.ConfirmedTranscriptHash)
	digest.Write(authData)
	next.InterimTranscriptHash = digest.Sum(nil)

	return next, nil
}

///// protect/unprotect and helpers

func (s State) verifyConfirmation(confirmation []byte) bool {
	hmac := s.CipherSuite.NewHMAC(s.Keys.ConfirmationKey)
	hmac.Write(s.ConfirmedTranscriptHash)
	confirm := hmac.Sum(nil)
	if !bytes.Equal(confirm, confirmation) {
		return false
	}
	return true
}

func applyGuard(nonceIn []byte, reuseGuard [4]byte) []byte {
	nonceOut := dup(nonceIn)
	for i := range reuseGuard {
		nonceOut[i] ^= reuseGuard[i]
	}
	return nonceOut
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

	var reuseGuard [4]byte
	rand.Read(reuseGuard[:])

	stream := syntax.NewWriteStream()
	err := stream.WriteAll(s.Index, generation, reuseGuard)
	if err != nil {
		return nil, fmt.Errorf("mls.state: sender data marshal failure %v", err)
	}

	senderData := stream.Data()
	senderDataNonce := make([]byte, s.CipherSuite.Constants().NonceSize)
	rand.Read(senderDataNonce)
	senderDataAADVal := senderDataAAD(s.GroupID, s.Epoch, pt.Content.Type(), senderDataNonce)
	sdAead, _ := s.CipherSuite.NewAEAD(s.Keys.SenderDataKey)
	sdCt := sdAead.Seal(nil, senderDataNonce, senderData, senderDataAADVal)

	// content data
	stream = syntax.NewWriteStream()
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
	aead, _ := s.CipherSuite.NewAEAD(keys.Key)
	contentCt := aead.Seal(nil, applyGuard(keys.Nonce, reuseGuard), content, aad)

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
	sdAead, _ := s.CipherSuite.NewAEAD(s.Keys.SenderDataKey)
	sd, err := sdAead.Open(nil, ct.SenderDataNonce, ct.EncryptedSenderData, sdAAD)
	if err != nil {
		return nil, fmt.Errorf("mls.state: senderData decryption failure %v", err)
	}

	// parse the senderData
	var sender LeafIndex
	var generation uint32
	var reuseGuard [4]byte
	stream := syntax.NewReadStream(sd)
	_, err = stream.ReadAll(&sender, &generation, &reuseGuard)
	if err != nil {
		return nil, fmt.Errorf("mls.state: senderData unmarshal failure %v", err)
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
	aead, _ := s.CipherSuite.NewAEAD(keys.Key)
	content, err := aead.Open(nil, applyGuard(keys.Nonce, reuseGuard), ct.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("mls.state: content decryption failure %v", err)
	}

	// parse the Content and Signature
	stream = syntax.NewReadStream(content)
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
		Sender:            Sender{SenderTypeMember, uint32(sender)},
		AuthenticatedData: ct.AuthenticatedData,
		Content:           mlsContent,
		Signature:         signature,
	}
	return pt, nil
}

func (s *State) Protect(data []byte) (*MLSCiphertext, error) {
	pt := &MLSPlaintext{
		GroupID: s.GroupID,
		Epoch:   s.Epoch,
		Sender:  Sender{SenderTypeMember, uint32(s.Index)},
		Content: MLSPlaintextContent{
			Application: &ApplicationData{
				Data: data,
			},
		},
	}

	err := pt.sign(s.groupContext(), s.IdentityPriv, s.Scheme)
	if err != nil {
		return nil, err
	}
	return s.encrypt(pt)
}

func (s *State) Unprotect(ct *MLSCiphertext) ([]byte, error) {
	pt, err := s.decrypt(ct)
	if err != nil {
		return nil, err
	}

	sigPubKey, err := s.signerPublicKey(pt.Sender)
	if err != nil {
		return nil, err
	}

	if !pt.verify(s.groupContext(), sigPubKey, s.Scheme) {
		return nil, fmt.Errorf("invalid message signature")
	}

	if pt.Content.Type() != ContentTypeApplication {
		return nil, fmt.Errorf("unprotect attempted on non-application message")
	}
	return pt.Content.Application.Data, nil
}

func senderDataAAD(gid []byte, epoch Epoch, contentType ContentType, nonce []byte) []byte {
	s := syntax.NewWriteStream()
	err := s.Write(struct {
		GroupID         []byte `tls:"head=1"`
		Epoch           Epoch
		ContentType     ContentType
		SenderDataNonce []byte `tls:"head=1"`
	}{
		GroupID:         gid,
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

	s := syntax.NewWriteStream()
	err := s.Write(struct {
		GroupID             []byte `tls:"head=1"`
		Epoch               Epoch
		ContentType         ContentType
		AuthenticatedData   []byte `tls:"head=4"`
		SenderDataNonce     []byte `tls:"head=1"`
		EncryptedSenderData []byte `tls:"head=1"`
	}{
		GroupID:             gid,
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

func (s State) Clone() *State {
	// Note: all the slice/map copy operations below on state are mere
	// reference copies.
	clone := &State{
		CipherSuite:             s.CipherSuite,
		GroupID:                 dup(s.GroupID),
		Epoch:                   s.Epoch,
		Tree:                    s.Tree.Clone(),
		ConfirmedTranscriptHash: nil,
		InterimTranscriptHash:   dup(s.InterimTranscriptHash),
		Keys:                    s.Keys,
		Index:                   s.Index,
		IdentityPriv:            s.IdentityPriv,
		TreePriv:                s.TreePriv.Clone(),
		Scheme:                  s.Scheme,
		PendingUpdates:          s.PendingUpdates,
		PendingProposals:        make([]MLSPlaintext, len(s.PendingProposals)),
		NewCredentials:          map[LeafIndex]bool{},
	}

	copy(clone.PendingProposals, s.PendingProposals)
	return clone
}

// Compare the public and shared private aspects of two nodes
func (s State) Equals(o State) bool {
	suite := s.CipherSuite == o.CipherSuite
	groupID := bytes.Equal(s.GroupID, o.GroupID)
	epoch := s.Epoch == o.Epoch
	tree := s.Tree.Equals(o.Tree)
	cth := bytes.Equal(s.ConfirmedTranscriptHash, o.ConfirmedTranscriptHash)
	ith := bytes.Equal(s.InterimTranscriptHash, o.InterimTranscriptHash)
	keys := reflect.DeepEqual(s.Keys, o.Keys)

	return suite && groupID && epoch && tree && cth && ith && keys
}

// Isolated getters and setters for public and secret state
//
// Note that the get/set operations here are very shallow.  We basically assume
// that the StateSecrets object is temporary, as a carrier for marshaling /
// unmarshaling.
type StateSecrets struct {
	CipherSuite CipherSuite

	// Per-participant non-secret state
	Index            LeafIndex
	InitPriv         HPKEPrivateKey
	IdentityPriv     SignaturePrivateKey
	Scheme           SignatureScheme
	PendingProposals []MLSPlaintext `tls:"head=4"`

	// Secret state
	PendingUpdates map[ProposalRef]updateSecrets `tls:"head=4"`
	Keys           keyScheduleEpoch
	TreePriv       TreeKEMPrivateKey
}

func NewStateFromWelcomeAndSecrets(welcome Welcome, ss StateSecrets) (*State, error) {
	// Import the base data using some information from the secrets
	suite := ss.CipherSuite
	epochSecret := ss.Keys.EpochSecret
	s, _, confirmation, err := NewStateFromWelcome(suite, epochSecret, welcome)
	if err != nil {
		return nil, err
	}

	// Import the secrets
	s.SetSecrets(ss)

	// Verify the confirmation
	if !s.verifyConfirmation(confirmation) {
		return nil, fmt.Errorf("mls.state: Confirmation failed to verify")
	}

	return s, nil
}

func (s *State) SetSecrets(ss StateSecrets) {
	s.CipherSuite = ss.CipherSuite
	s.Index = ss.Index
	s.IdentityPriv = ss.IdentityPriv
	s.Scheme = ss.Scheme
	s.PendingProposals = ss.PendingProposals
	s.Keys = ss.Keys
	s.TreePriv = ss.TreePriv

	s.TreePriv.privateKeyCache = map[NodeIndex]HPKEPrivateKey{}

	s.PendingUpdates = map[ProposalRef]updateSecrets{}
	for i, secret := range ss.PendingUpdates {
		s.PendingUpdates[i] = secret
	}
}

func (s State) GetSecrets() StateSecrets {
	pendingUpdates := map[ProposalRef]updateSecrets{}
	for i, secret := range s.PendingUpdates {
		pendingUpdates[i] = secret
	}

	return StateSecrets{
		CipherSuite:      s.CipherSuite,
		Index:            s.Index,
		IdentityPriv:     s.IdentityPriv,
		Scheme:           s.Scheme,
		PendingProposals: s.PendingProposals,
		PendingUpdates:   pendingUpdates,
		Keys:             s.Keys,
		TreePriv:         s.TreePriv,
	}
}
