package mls

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
)

var (
	labelMessageRootKey = "message root key"
	labelUpdateSecret   = "update secret"
	labelUpdateKey      = "update key"
	labelDeleteKey      = "delete secret"
	labelEpochSecret    = "epoch secret"
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
	myLeafKey     ECPrivateKey
	myIdentityKey ECPrivateKey

	// Description of the group
	epoch        uint
	groupID      []byte
	identityTree *tree
	leafTree     *tree
	ratchetTree  *tree
	leafList     []ECPublicKey

	// Secrets for the current epoch
	messageRootKey []byte
	updateSecret   []byte
	updateKey      ECPrivateKey
	deleteKey      ECPrivateKey
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
	updateKey := bytes.Equal(lhs.updateKey.PublicKey.bytes(), rhs.updateKey.PublicKey.bytes())
	deleteKey := bytes.Equal(lhs.deleteKey.PublicKey.bytes(), rhs.deleteKey.PublicKey.bytes())

	// XXX Uncomment for helpful debug info
	//fmt.Printf("%v %v %v %v %v %v %v %v %v \n", epoch, groupID, identityTree, leafTree, ratchetTree, messageRootKey, updateSecret, updateKey, deleteKey)

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

func NewStateForEmptyGroup(groupID []byte, identityKey ECPrivateKey) (*State, error) {
	state := &State{
		myIndex:       0,
		myLeafKey:     NewECKey().PrivateKey,
		myIdentityKey: identityKey,

		epoch:        0,
		groupID:      groupID,
		identityTree: newTree(merkleNodeDefn),
		leafTree:     newTree(merkleNodeDefn),
		ratchetTree:  newTree(ecdhNodeDefn),
		leafList:     []ECPublicKey{identityKey.PublicKey},

		messageRootKey: nil,
		updateSecret:   nil,
		updateKey:      NewECKey().PrivateKey,
		deleteKey:      NewECKey().PrivateKey,
	}

	err := state.identityTree.Add(merkleLeaf(state.myIdentityKey.PublicKey.bytes()))
	if err != nil {
		return nil, err
	}

	err = state.leafTree.Add(merkleLeaf(state.myLeafKey.PublicKey.bytes()))
	if err != nil {
		return nil, err
	}

	err = state.ratchetTree.Add(ECKeyFromPrivateKey(state.myLeafKey))
	if err != nil {
		return nil, err
	}

	return state, nil
}

func NewStateFromGroupAdd(identityKey ECPrivateKey, preKey ECPrivateKey, signedGroupAdd *RosterSigned, priorGPK *RosterSigned) (*State, error) {
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

	if !groupAdd.PreKey.PublicKey.Equal(identityKey.PublicKey) {
		return nil, fmt.Errorf("PreKey signed by wrong identity key")
	}

	// Generate the leaf key and add to the state
	leafKey := ECKeyFromData(preKey.derive(groupPreKey.UpdateKey)).PrivateKey

	return newStateFromVerifiedDetails(identityKey, leafKey, groupPreKey)
}

func NewStateFromGroupPreKey(identityKey ECPrivateKey, leafKey ECPrivateKey, priorGPK *RosterSigned) (*State, error) {
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

func newStateFromVerifiedDetails(identityKey ECPrivateKey, leafKey ECPrivateKey, groupPreKey *GroupPreKey) (*State, error) {
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

	err = identityTree.Add(merkleLeaf(identityKey.PublicKey.bytes()))
	if err != nil {
		return nil, err
	}

	err = leafTree.Add(merkleLeaf(leafKey.PublicKey.bytes()))
	if err != nil {
		return nil, err
	}

	err = ratchetTree.Add(ECKeyFromPrivateKey(leafKey))
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
	epochSecret := treeKey.PrivateKey.derive(groupPreKey.UpdateKey)
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
		UpdateKey:        s.updateKey.PublicKey,
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
	s.updateKey = ECKeyFromData(kdf(labelUpdateKey, epochSecret)).PrivateKey
	s.deleteKey = ECKeyFromData(kdf(labelDeleteKey, epochSecret)).PrivateKey
}

///
/// Functions to generate epoch-changing messages
///

func Join(identityKey ECPrivateKey, leafKey ECPrivateKey, oldGPK *RosterSigned) (*RosterSigned, *RosterSigned, error) {
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

	addPath := make([]ECPublicKey, len(abstractAddPath))
	for i, n := range abstractAddPath {
		addPath[i] = n.(*ECKey).PrivateKey.PublicKey
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

func (s State) Update(leafKey ECPrivateKey) (*RosterSigned, error) {
	leafPath, err := s.leafTree.UpdatePath(s.myIndex, merkleLeaf(leafKey.PublicKey.bytes()))
	if err != nil {
		return nil, err
	}

	ratchetPath, err := s.ratchetTree.UpdatePath(s.myIndex, ECKeyFromPrivateKey(leafKey))
	if err != nil {
		return nil, err
	}

	update := Update{
		LeafPath:    make([][]byte, len(leafPath)),
		RatchetPath: make([]ECPublicKey, len(ratchetPath)),
	}
	for i, n := range leafPath {
		update.LeafPath[i] = n.([]byte)
	}
	for i, n := range ratchetPath {
		update.RatchetPath[i] = n.(*ECKey).PrivateKey.PublicKey
	}

	return s.sign(update)
}

func (s State) Delete(indices []uint) (*RosterSigned, error) {
	hasLeaves := (len(s.leafList) > 0)
	hasIdentities := s.identityTree.HasAllLeaves()
	if !hasLeaves || !hasIdentities {
		return nil, fmt.Errorf("Cannot delete without having all leaves and identities")
	}

	deleted := map[uint]bool{}
	for _, i := range indices {
		deleted[i] = true
	}

	head := s.updateKey
	path := []ECPublicKey{}

	for i, leafKey := range s.leafList {
		if deleted[uint(i)] {
			continue
		}

		headData := head.derive(leafKey)
		newHead := ECKeyFromData(headData).PrivateKey

		head = newHead
		path = append(path, head.PublicKey)
	}

	abstractIdentities, err := s.identityTree.Leaves()
	if err != nil {
		return nil, err
	}

	identities := make([][]byte, len(abstractIdentities))
	for i, id := range abstractIdentities {
		identities[i] = id.([]byte)
	}

	delete := Delete{
		Deleted:    indices,
		Path:       path,
		Leaves:     s.leafList,
		Identities: identities,
	}

	return s.sign(delete)
}

///
/// Functions to handle epoch-changing messages
///

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
		addPath[i] = ECKeyFromPublicKey(n)
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
	leafKey := ECKeyFromData(leafData).PrivateKey

	err = s.ratchetTree.Add(ECKeyFromPrivateKey(leafKey))
	if err != nil {
		return err
	}

	// Update other state
	return s.addToSymmetricState(identityKey, leafKey.PublicKey)
}

func (s *State) addToSymmetricState(identityKey, leafKey ECPublicKey) error {
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
	epochSecret := treeKey.PrivateKey.derive(s.updateKey.PublicKey)
	s.deriveEpochKeys(epochSecret)
	return nil
}

func (s *State) HandleSelfUpdate(leafKey ECPrivateKey, signedUpdate *RosterSigned) error {
	err := s.handleUpdateInner(signedUpdate, &leafKey)
	if err != nil {
		return err
	}

	s.myLeafKey = leafKey
	return nil
}

func (s *State) HandleUpdate(signedUpdate *RosterSigned) error {
	return s.handleUpdateInner(signedUpdate, nil)
}

func (s *State) handleUpdateInner(signedUpdate *RosterSigned, leafKey *ECPrivateKey) error {
	update := new(Update)
	err := s.verifyForCurrentRoster(signedUpdate, update)
	if err != nil {
		return err
	}

	// Update leaf tree
	index := signedUpdate.Copath.Index
	leafPath := make([]Node, len(update.LeafPath))
	for i, n := range update.LeafPath {
		leafPath[i] = n
	}

	err = s.leafTree.UpdateWithPath(index, leafPath)
	if err != nil {
		return err
	}

	// Update ratchet tree
	ratchetPath := make([]Node, len(update.RatchetPath))
	for i, n := range update.RatchetPath {
		ratchetPath[i] = ECKeyFromPublicKey(n)
	}
	if leafKey != nil {
		ratchetPath[len(ratchetPath)-1] = ECKeyFromPrivateKey(*leafKey)
	}

	err = s.ratchetTree.UpdateWithPath(index, ratchetPath)
	if err != nil {
		return err
	}

	// Update leaf list (if applicable)
	if len(s.leafList) > 0 {
		s.leafList[index] = update.RatchetPath[len(update.RatchetPath)-1]
	}

	// Update group secrets
	rootNode, err := s.ratchetTree.Root()
	if err != nil {
		return err
	}

	treeKey := rootNode.(*ECKey).Data
	epochSecret := kdf(labelEpochSecret, s.updateSecret, treeKey)
	s.deriveEpochKeys(epochSecret)
	s.epoch += 1
	return nil
}

func (s *State) importIdentities(identities [][]byte) error {
	leaves := make([]Node, len(identities))
	for i, id := range identities {
		leaves[i] = id
	}

	t, err := newTreeFromLeaves(merkleNodeDefn, leaves)
	if err != nil {
		return err
	}

	err = compareTreeRoots(s.identityTree, t)
	if err != nil {
		return err
	}

	s.identityTree = t
	return nil
}

func (s *State) importLeaves(leafKeys []ECPublicKey) error {
	leaves := make([]Node, len(leafKeys))
	for i, leafKey := range leafKeys {
		leaves[i] = merkleLeaf(leafKey.bytes())
	}

	t, err := newTreeFromLeaves(merkleNodeDefn, leaves)
	if err != nil {
		return err
	}

	err = compareTreeRoots(s.leafTree, t)
	if err != nil {
		return err
	}

	s.leafTree = t
	s.leafList = leafKeys
	return nil
}

func compareTreeRoots(local, remote *tree) error {
	localRoot, err := local.Root()
	if err != nil {
		return err
	}

	remoteRoot, err := remote.Root()
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(localRoot, remoteRoot) {
		return fmt.Errorf("Tree root mismatch")
	}

	return nil
}

func (s *State) HandleDelete(signedDelete *RosterSigned) error {
	delete := new(Delete)
	err := s.verifyForCurrentRoster(signedDelete, delete)
	if err != nil {
		return err
	}

	deleted := map[uint]bool{}
	for _, i := range delete.Deleted {
		deleted[i] = true
	}

	// Verify and import lists of leaf and identity keys
	err = s.importLeaves(delete.Leaves)
	if err != nil {
		return err
	}

	err = s.importIdentities(delete.Identities)
	if err != nil {
		return err
	}

	// Compute a secret that is not available to the deleted nodes
	curr := 0
	var headData []byte
	for i, leafKey := range s.leafList {
		switch {
		case deleted[uint(i)]:
			continue

		case i < int(s.myIndex):
			curr += 1
			continue

		case i == int(s.myIndex):
			prevPub := s.updateKey.PublicKey
			if curr > 0 {
				prevPub = delete.Path[curr-1]
			}
			headData = s.myLeafKey.derive(prevPub)

		default:
			head := ECKeyFromData(headData).PrivateKey
			headData = head.derive(leafKey)
		}
	}

	// Replace the delelted nodes with the delete key in the ratchet tree
	// Replace the deleted nodes with empty nodes in the identity tree
	emptyNode := emptyMerkleLeaf()
	deleteNode := ECKeyFromPublicKey(s.deleteKey.PublicKey)
	for i := range deleted {
		err := s.identityTree.Update(i, emptyNode)
		if err != nil {
			return err
		}

		// XXX this should be a method, e.g., SetWithoutBuild(i, deleteKey
		s.ratchetTree.nodes[2*i] = deleteNode
	}

	// Ratchet the epoch forward
	epochSecret := kdf(labelEpochSecret, s.updateSecret, headData)
	s.deriveEpochKeys(epochSecret)
	s.epoch += 1
	return nil
}
