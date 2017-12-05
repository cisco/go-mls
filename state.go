package mls

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

var (
	labelMessageRootKey = "message root key"
	labelUpdateSecret   = "update secret"
	labelUpdateKey      = "update key"
	labelDeleteKey      = "delete secret"
)

// TODO Use a real KDF
func kdf(label string, data ...[]byte) []byte {
	h := sha256.New()
	h.Write([]byte(label))
	h.Write([]byte{0x00})
	for _, buf := range data {
		h.Write(buf)
	}
	return h.Sum(nil)
}

func rootForSignedGPK(signedGPK *RosterSigned) ([]byte, error) {
	groupPreKey := new(GroupPreKey)
	err := signedGPK.Verify(groupPreKey, nil)
	if err != nil {
		return nil, err
	}

	identityTree, err := newTreeFromFrontier(groupPreKey.IdentityFrontier.Frontier())
	if err != nil {
		return nil, err
	}

	rootNode, err := identityTree.Root()
	if err != nil {
		return nil, err
	}
	return rootNode.([]byte), nil
}

type State struct {
	// Details for this node
	myIndex       uint
	myLeafKey     *ECKey
	myIdentityKey *ECKey

	// Description of the group
	epoch        uint
	groupID      []byte
	identityTree *tree
	leafTree     *tree
	ratchetTree  *tree
	leafList     []*ECKey

	// Secrets for the current epoch
	messageRootKey []byte
	updateSecret   []byte
	updateKey      *ECKey
	deleteKey      *ECKey
}

// Only check the shared components
func (lhs State) Equal(rhs *State) bool {
	epoch := (lhs.epoch == rhs.epoch)
	groupID := bytes.Equal(lhs.groupID, rhs.groupID)
	identityTree := lhs.identityTree.Equal(rhs.identityTree)
	leafTree := lhs.leafTree.Equal(rhs.leafTree)
	ratchetTree := lhs.ratchetTree.Equal(rhs.ratchetTree)
	messageRootKey := bytes.Equal(lhs.messageRootKey, rhs.messageRootKey)
	updateSecret := bytes.Equal(lhs.updateSecret, rhs.updateSecret)
	updateKey := bytes.Equal(lhs.updateKey.bytes(), rhs.updateKey.bytes())
	deleteKey := bytes.Equal(lhs.deleteKey.bytes(), rhs.deleteKey.bytes())

	return epoch &&
		groupID &&
		identityTree &&
		leafTree &&
		ratchetTree &&
		messageRootKey &&
		updateSecret &&
		updateKey &&
		deleteKey
}

func NewStateForEmptyGroup(groupID []byte, identityKey *ECKey) (*State, error) {
	state := &State{
		myIndex:       0,
		myLeafKey:     NewECKey(),
		myIdentityKey: identityKey,

		epoch:        0,
		groupID:      groupID,
		identityTree: newTree(merkleNodeDefn),
		leafTree:     newTree(merkleNodeDefn),
		ratchetTree:  newTree(ecdhNodeDefn),
		leafList:     []*ECKey{},

		messageRootKey: nil,
		updateSecret:   nil,
		updateKey:      NewECKey(),
		deleteKey:      NewECKey(),
	}

	err := state.identityTree.Add(merkleLeaf(state.myIdentityKey.bytes()))
	if err != nil {
		return nil, err
	}

	err = state.leafTree.Add(merkleLeaf(state.myLeafKey.bytes()))
	if err != nil {
		return nil, err
	}

	err = state.ratchetTree.Add(state.myLeafKey)
	if err != nil {
		return nil, err
	}

	return state, nil
}

func NewStateFromGroupAdd(identityKey *ECKey, preKey *ECKey, signedGroupAdd *RosterSigned, priorGPK *RosterSigned) (*State, error) {
	priorRoot, err := rootForSignedGPK(priorGPK)
	if err != nil {
		return nil, err
	}

	// Verify the GroupAdd and GroupPreKey against the previous root
	groupPreKey := new(GroupPreKey)
	err = priorGPK.Verify(groupPreKey, priorRoot)
	if err != nil {
		return nil, err
	}

	groupAdd := new(GroupAdd)
	err = signedGroupAdd.Verify(groupAdd, priorRoot)
	if err != nil {
		return nil, err
	}

	if !ecdhNodeDefn.publicEqual(groupAdd.PreKey.PublicKey, identityKey) {
		return nil, fmt.Errorf("PreKey signed by wrong identity key")
	}

	// Generate the leaf key and add to the state
	leafKey := ECKeyFromData(preKey.derive(groupPreKey.UpdateKey))

	return newStateFromVerifiedDetails(identityKey, leafKey, groupPreKey)
}

func NewStateFromGroupPreKey(identityKey *ECKey, leafKey *ECKey, priorGPK *RosterSigned) (*State, error) {
	priorRoot, err := rootForSignedGPK(priorGPK)
	if err != nil {
		return nil, err
	}

	// Verify the GroupAdd against the previous root
	groupPreKey := new(GroupPreKey)
	err = priorGPK.Verify(groupPreKey, priorRoot)
	if err != nil {
		return nil, err
	}

	return newStateFromVerifiedDetails(identityKey, leafKey, groupPreKey)
}

func newStateFromVerifiedDetails(identityKey *ECKey, leafKey *ECKey, groupPreKey *GroupPreKey) (*State, error) {
	// Initialize trees and add this node
	identityTree, err := newTreeFromFrontier(groupPreKey.IdentityFrontier.Frontier())
	if err != nil {
		return nil, err
	}

	leafTree, err := newTreeFromFrontier(groupPreKey.LeafFrontier.Frontier())
	if err != nil {
		return nil, err
	}

	ratchetTree, err := newTreeFromFrontier(groupPreKey.RatchetFrontier.Frontier())
	if err != nil {
		return nil, err
	}

	err = identityTree.Add(merkleLeaf(identityKey.bytes()))
	if err != nil {
		return nil, err
	}

	err = leafTree.Add(merkleLeaf(leafKey.bytes()))
	if err != nil {
		return nil, err
	}

	err = ratchetTree.Add(leafKey)
	if err != nil {
		return nil, err
	}

	// Assemble the state object
	s := &State{
		myIndex:       identityTree.size - 1,
		myLeafKey:     leafKey,
		myIdentityKey: identityKey,

		epoch:        groupPreKey.Epoch + 1,
		groupID:      groupPreKey.GroupID,
		identityTree: identityTree,
		leafTree:     leafTree,
		ratchetTree:  ratchetTree,
	}

	// Generate group secrets
	rootNode, err := s.ratchetTree.Root()
	if err != nil {
		return nil, err
	}

	treeKey := rootNode.(*ECKey)
	epochSecret := treeKey.derive(groupPreKey.UpdateKey)
	s.deriveEpochKeys(epochSecret)
	return s, nil
}

///
/// Convenience functions
///

func (s State) sign(body interface{}) (*RosterSigned, error) {
	copath, err := s.identityTree.Copath(s.myIndex)
	if err != nil {
		return nil, err
	}

	return NewRosterSigned(body, s.myIdentityKey, copath)
}

func (s State) verifyForCurrentRoster(rs *RosterSigned, out interface{}) error {
	rootNode, err := s.identityTree.Root()
	if err != nil {
		return err
	}

	root := rootNode.([]byte)
	return rs.Verify(out, root)
}

func (s State) groupPreKey() (*RosterSigned, error) {
	// XXX: Ignoring errors
	ifr, _ := s.identityTree.Frontier()
	lfr, _ := s.leafTree.Frontier()
	rfr, _ := s.ratchetTree.Frontier()

	Ifr, _ := NewMerkleFrontier(ifr)
	Lfr, _ := NewMerkleFrontier(lfr)
	Rfr, _ := NewECFrontier(rfr)

	gpk := &GroupPreKey{
		Epoch:            s.epoch,
		GroupID:          s.groupID,
		UpdateKey:        s.updateKey,
		IdentityFrontier: Ifr,
		LeafFrontier:     Lfr,
		RatchetFrontier:  Rfr,
	}

	return s.sign(gpk)
}

func (s *State) deriveEpochKeys(epochSecret []byte) {
	// TODO: Hash in additional context, e.g.:
	// * Key management messages
	// * Identity tree root
	s.messageRootKey = kdf(labelMessageRootKey, epochSecret)
	s.updateSecret = kdf(labelUpdateSecret, epochSecret)
	s.updateKey = ECKeyFromData(kdf(labelUpdateKey, epochSecret))
	s.deleteKey = ECKeyFromData(kdf(labelDeleteKey, epochSecret))
}

func Join(identityKey *ECKey, leafKey *ECKey, oldGPK *RosterSigned) (*RosterSigned, *RosterSigned, error) {
	// Construct a temporary state as if we had already joined
	s, err := NewStateFromGroupPreKey(identityKey, leafKey, oldGPK)
	if err != nil {
		return nil, nil, err
	}

	// Extract the direct ratchet path for the new node
	abstractAddPath, err := s.ratchetTree.DirectPath(s.myIndex)
	if err != nil {
		return nil, nil, err
	}

	addPath := make([]*ECKey, len(abstractAddPath))
	for i, n := range abstractAddPath {
		addPath[i] = n.(*ECKey)
	}

	add := UserAdd{AddPath: addPath}
	signedAdd, err := s.sign(add)
	if err != nil {
		return nil, nil, err
	}

	newGPK, err := s.groupPreKey()
	if err != nil {
		return nil, nil, err
	}

	return signedAdd, newGPK, nil
}

func (s State) Add(signedUserPreKey *Signed) (*RosterSigned, error) {
	userPreKey := new(UserPreKey)
	err := signedUserPreKey.Verify(userPreKey)
	if err != nil {
		return nil, err
	}

	groupAdd := &GroupAdd{
		PreKey: signedUserPreKey,
	}

	return s.sign(groupAdd)
}

// TODO Update(leafKey *ECKey) (RosterSigned<Update>)
// TODO Delete(indices []uint) (RosterSigned<Delete>)

func (s *State) HandleUserAdd(signedUserAdd *RosterSigned, signedNewGPK *RosterSigned) error {
	// TODO Verify that the new identity tree is a successor to the old one
	newIdentityRoot, err := rootForSignedGPK(signedNewGPK)
	if err != nil {
		return err
	}

	// Verify the UserAdd and GroupPreKey against the previous root
	userAdd := new(UserAdd)
	err = signedUserAdd.Verify(userAdd, newIdentityRoot)
	if err != nil {
		return err
	}

	groupPreKey := new(GroupPreKey)
	err = signedNewGPK.Verify(groupPreKey, newIdentityRoot)
	if err != nil {
		return err
	}

	// Update ratchet tree
	addPath := make([]Node, len(userAdd.AddPath))
	for i, n := range userAdd.AddPath {
		addPath[i] = n
	}
	err = s.ratchetTree.AddWithPath(addPath)

	// Update other state
	identityKey := signedUserAdd.Signed.PublicKey
	leafKey := userAdd.AddPath[len(userAdd.AddPath)-1]

	return s.addToSymmetricState(identityKey, leafKey)
}

func (s *State) HandleGroupAdd(signedGroupAdd *RosterSigned) error {
	groupAdd := new(GroupAdd)
	err := s.verifyForCurrentRoster(signedGroupAdd, groupAdd)
	if err != nil {
		return err
	}

	userPreKey := new(UserPreKey)
	err = groupAdd.PreKey.Verify(userPreKey)
	if err != nil {
		return err
	}

	preKey := userPreKey.PreKey
	identityKey := groupAdd.PreKey.PublicKey

	// Derive the new leaf and add it to the ratchet tree
	leafData := s.updateKey.derive(preKey)
	leafKey := ECKeyFromData(leafData)

	err = s.ratchetTree.Add(leafKey)
	if err != nil {
		return err
	}

	// Update other state
	return s.addToSymmetricState(identityKey, leafKey)
}

func (s *State) addToSymmetricState(identityKey, leafKey *ECKey) error {
	s.epoch += 1

	err := s.identityTree.Add(merkleLeaf(identityKey.bytes()))
	if err != nil {
		return err
	}

	err = s.leafTree.Add(merkleLeaf(leafKey.bytes()))
	if err != nil {
		return err
	}

	if len(s.leafList) > 0 {
		s.leafList = append(s.leafList, leafKey)
	}

	// Update group secrets
	rootNode, err := s.ratchetTree.Root()
	if err != nil {
		return err
	}

	treeKey := rootNode.(*ECKey)
	epochSecret := treeKey.derive(s.updateKey)
	s.deriveEpochKeys(epochSecret)
	return nil
}

// func (s *State) HandleUpdate(update RosterSigned<Update>, leafKey *ECKey) error
// func (s *State) HandleUpdate(update RosterSigned<Update>) error
// func (s *State) HandleDelete(delete RosterSigned<Delete>) error
