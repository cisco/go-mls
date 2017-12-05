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

	// XXX DELE
	//fmt.Println(epoch, groupID, identityTree, leafTree, ratchetTree, messageRootKey, updateSecret, updateKey, deleteKey)

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
	groupPreKey := new(GroupPreKey)
	err := priorGPK.Verify(groupPreKey, nil)
	if err != nil {
		return nil, err
	}

	// Initialize to emulate the last state
	s := &State{
		epoch:     groupPreKey.Epoch,
		groupID:   groupPreKey.GroupID,
		updateKey: groupPreKey.UpdateKey,
	}

	s.identityTree, err = newTreeFromFrontier(groupPreKey.IdentityFrontier.Frontier())
	if err != nil {
		return nil, err
	}

	s.leafTree, err = newTreeFromFrontier(groupPreKey.LeafFrontier.Frontier())
	if err != nil {
		return nil, err
	}

	s.ratchetTree, err = newTreeFromFrontier(groupPreKey.RatchetFrontier.Frontier())
	if err != nil {
		return nil, err
	}

	// Verify the groupAdd against the last state
	groupAdd := new(GroupAdd)
	err = s.verifyForCurrentRoster(signedGroupAdd, groupAdd)
	if err != nil {
		return nil, err
	}

	if !ecdhNodeDefn.equal(groupAdd.PreKey.PublicKey, identityKey) {
		return nil, fmt.Errorf("PreKey signed by wrong identity key")
	}

	// Generate the leaf key and add to the state
	leafKey := ECKeyFromData(preKey.derive(s.updateKey))

	s.myIndex = s.identityTree.size
	s.myLeafKey = leafKey
	s.myIdentityKey = identityKey
	s.epoch += 1

	err = s.identityTree.Add(merkleLeaf(s.myIdentityKey.bytes()))
	if err != nil {
		return nil, err
	}

	err = s.leafTree.Add(merkleLeaf(s.myLeafKey.bytes()))
	if err != nil {
		return nil, err
	}

	err = s.ratchetTree.Add(s.myLeafKey)
	if err != nil {
		return nil, err
	}

	// Generate group secrets
	rootNode, err := s.ratchetTree.Root()
	if err != nil {
		return nil, err
	}

	treeKey := rootNode.(*ECKey)
	epochSecret := treeKey.derive(s.updateKey)
	s.deriveEpochKeys(epochSecret)
	return s, nil
}

// TODO
// NewStateFromGroupPreKey(identityKey *ECKey, leafKey *ECKey, priorGPK *RosterSigned<GroupPreKey>) (*State, error)

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

// TODO
// Join(identityKey *ECKey, leafKey *ECKey, groupPreKey *GroupPreKey) (Signed<UserAdd>, RosterSigned<GroupPreKey>)

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
//
// TODO HandleUserAdd(userAdd Signed<UserAdd>, newGPK RosterSigned<GroupPreKey>) error

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

	// Derive the new leaf
	leafData := s.updateKey.derive(preKey)
	leafKey := ECKeyFromData(leafData)

	// Update trees to the next epoch
	s.epoch += 1

	err = s.identityTree.Add(merkleLeaf(identityKey.bytes()))
	if err != nil {
		return err
	}

	err = s.leafTree.Add(merkleLeaf(leafKey.bytes()))
	if err != nil {
		return err
	}

	err = s.ratchetTree.Add(leafKey)
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

// HandleUpdate(update RosterSigned<Update>, leafKey *ECKey) error
// HandleUpdate(update RosterSigned<Update>) error
// HandleDelete(delete RosterSigned<Delete>) error
//
