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

type State struct {
	// Details for this node
	myIndex       uint
	myLeafKey     DHPrivateKey
	myIdentityKey SignaturePrivateKey

	// Description of the group
	epoch        uint32
	groupID      []byte
	identityTree *tree
	leafTree     *tree
	ratchetTree  *tree
	leafList     []DHPublicKey

	// Secrets for the current epoch
	messageRootKey []byte
	updateSecret   []byte
	updateKey      DHPrivateKey
	deleteKey      DHPrivateKey
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
	updateKey := lhs.updateKey.PublicKey.Equal(rhs.updateKey.PublicKey)
	deleteKey := lhs.deleteKey.PublicKey.Equal(rhs.deleteKey.PublicKey)

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

func NewStateForEmptyGroup(groupID []byte, identityKey SignaturePrivateKey) (*State, error) {
	state := &State{
		myIndex:       0,
		myLeafKey:     NewDHPrivateKey(),
		myIdentityKey: identityKey,

		epoch:        0,
		groupID:      groupID,
		identityTree: newTree(merkleNodeDefn),
		leafTree:     newTree(merkleNodeDefn),
		ratchetTree:  newTree(dhNodeDefn),
		leafList:     []DHPublicKey{},

		messageRootKey: nil,
		updateSecret:   nil,
		updateKey:      NewDHPrivateKey(),
		deleteKey:      NewDHPrivateKey(),
	}

	err := state.identityTree.Add(NewMerkleNode(state.myIdentityKey.PublicKey))
	if err != nil {
		return nil, err
	}

	err = state.leafTree.Add(NewMerkleNode(state.myLeafKey.PublicKey))
	if err != nil {
		return nil, err
	}

	err = state.ratchetTree.Add(DHNodeFromPrivateKey(state.myLeafKey))
	if err != nil {
		return nil, err
	}

	state.leafList = []DHPublicKey{state.myLeafKey.PublicKey}

	return state, nil
}

func NewStateFromGroupAdd(identityKey SignaturePrivateKey, preKey DHPrivateKey, signedGroupAdd *Handshake, priorGPK *Handshake) (*State, error) {
	// Verify the prior Handshake and GroupAdd against the previous root
	priorRoot, err := priorGPK.IdentityRoot()
	if err != nil {
		return nil, err
	}

	if err := priorGPK.Verify(priorRoot); err != nil {
		return nil, err
	}

	if err := signedGroupAdd.Verify(priorRoot); err != nil {
		return nil, err
	}

	groupAdd, ok := signedGroupAdd.Body.(*GroupAdd)
	if !ok {
		return nil, fmt.Errorf("NewStateFromGroupAdd was not provided with a GroupAdd")
	}

	if !groupAdd.PreKey.IdentityKey.Equal(identityKey.PublicKey) {
		return nil, fmt.Errorf("PreKey signed by wrong identity key")
	}

	// Generate the leaf key and add to the state
	leafKey := DHNodeFromData(preKey.derive(priorGPK.PreKey.UpdateKey)).PrivateKey

	return newStateFromVerifiedDetails(identityKey, leafKey, priorGPK.PreKey)
}

func NewStateFromGroupPreKey(identityKey SignaturePrivateKey, leafKey DHPrivateKey, priorGPK *Handshake) (*State, error) {
	// Verify the prior Handshake and GroupAdd against the previous root
	priorRoot, err := priorGPK.IdentityRoot()
	if err != nil {
		return nil, err
	}

	if err := priorGPK.Verify(priorRoot); err != nil {
		return nil, err
	}

	return newStateFromVerifiedDetails(identityKey, leafKey, priorGPK.PreKey)
}

func newStateFromVerifiedDetails(identityKey SignaturePrivateKey, leafKey DHPrivateKey, groupPreKey GroupPreKey) (*State, error) {
	treeSize := uint(groupPreKey.GroupSize)

	// Initialize trees and add this node
	identityTree, err := newTreeFromFrontier(merkleNodeDefn, treeSize, groupPreKey.IdentityFrontier.Nodes())
	if err != nil {
		return nil, err
	}

	leafTree, err := newTreeFromFrontier(merkleNodeDefn, treeSize, groupPreKey.LeafFrontier.Nodes())
	if err != nil {
		return nil, err
	}

	ratchetTree, err := newTreeFromFrontier(dhNodeDefn, treeSize, groupPreKey.RatchetFrontier.Nodes())
	if err != nil {
		return nil, err
	}

	err = identityTree.Add(NewMerkleNode(identityKey.PublicKey))
	if err != nil {
		return nil, err
	}

	err = leafTree.Add(NewMerkleNode(leafKey.PublicKey))
	if err != nil {
		return nil, err
	}

	err = ratchetTree.Add(DHNodeFromPrivateKey(leafKey))
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

	treeKey := rootNode.(*DHNode)
	epochSecret := treeKey.PrivateKey.derive(groupPreKey.UpdateKey)
	s.deriveEpochKeys(epochSecret)
	return s, nil
}

///
/// Convenience functions
///

func (s State) groupPreKey() GroupPreKey {
	// XXX: Ignoring errors
	ifr, _ := s.identityTree.Frontier()
	lfr, _ := s.leafTree.Frontier()
	rfr, _ := s.ratchetTree.Frontier()

	Ifr, _ := NewMerklePath(ifr)
	Lfr, _ := NewMerklePath(lfr)
	Rfr, _ := NewDHPath(rfr)

	return GroupPreKey{
		Epoch:            s.epoch,
		GroupID:          s.groupID,
		GroupSize:        uint32(s.identityTree.size),
		UpdateKey:        s.updateKey.PublicKey,
		IdentityFrontier: Ifr,
		LeafFrontier:     Lfr,
		RatchetFrontier:  Rfr,
	}
}

func (s State) sign(body HandshakeMessageBody) (*Handshake, error) {
	abstractCopath, err := s.identityTree.Copath(s.myIndex)
	if err != nil {
		return nil, err
	}

	copath, err := NewMerklePath(abstractCopath)
	if err != nil {
		return nil, err
	}

	h := &Handshake{
		Body:          body,
		PreKey:        s.groupPreKey(),
		SignerIndex:   uint32(s.myIndex),
		IdentityProof: copath,
		IdentityKey:   s.myIdentityKey.PublicKey,
	}

	if err := h.Sign(s.myIdentityKey); err != nil {
		return nil, err
	}

	return h, nil
}

func (s State) verifyForCurrentRoster(h *Handshake) error {
	rootNode, err := s.identityTree.Root()
	if err != nil {
		return err
	}

	root := rootNode.(MerkleNode).Value
	return h.Verify(root)
}

func (s *State) deriveEpochKeys(epochSecret []byte) {
	// TODO: Hash in additional context, e.g.:
	// * Handshake messages
	// * Identity tree root
	s.messageRootKey = kdf(labelMessageRootKey, epochSecret)
	s.updateSecret = kdf(labelUpdateSecret, epochSecret)
	s.updateKey = DHNodeFromData(kdf(labelUpdateKey, epochSecret)).PrivateKey
	s.deleteKey = DHNodeFromData(kdf(labelDeleteKey, epochSecret)).PrivateKey
}

///
/// Functions to generate handshake messages
///

func Join(identityKey SignaturePrivateKey, leafKey DHPrivateKey, oldGPK *Handshake) (*Handshake, error) {
	// Construct a temporary state as if we had already joined
	s, err := NewStateFromGroupPreKey(identityKey, leafKey, oldGPK)
	if err != nil {
		return nil, err
	}

	// Extract the direct ratchet path for the new node
	abstractAddPath, err := s.ratchetTree.DirectPath(s.myIndex)
	if err != nil {
		return nil, err
	}

	addPath := make([]DHPublicKey, len(abstractAddPath))
	for i, n := range abstractAddPath {
		addPath[i] = n.(*DHNode).PrivateKey.PublicKey
	}

	userAdd := &UserAdd{AddPath: addPath}
	return s.sign(userAdd)
}

func (s State) SignedGroupPreKey() (*Handshake, error) {
	return s.sign(None{})
}

func (s State) Add(userPreKey *UserPreKey) (*Handshake, error) {
	if err := userPreKey.Verify(); err != nil {
		return nil, err
	}

	groupAdd := &GroupAdd{
		PreKey: *userPreKey,
	}

	return s.sign(groupAdd)
}

func (s State) Update(leafKey DHPrivateKey) (*Handshake, error) {
	leafPath, err := s.leafTree.UpdatePath(s.myIndex, NewMerkleNode(leafKey.PublicKey))
	if err != nil {
		return nil, err
	}

	ratchetPath, err := s.ratchetTree.UpdatePath(s.myIndex, DHNodeFromPrivateKey(leafKey))
	if err != nil {
		return nil, err
	}

	update := &Update{}

	update.LeafPath, err = NewMerklePath(leafPath)
	if err != nil {
		return nil, err
	}

	update.RatchetPath, err = NewDHPath(ratchetPath)
	if err != nil {
		return nil, err
	}

	return s.sign(update)
}

func (s State) Delete(indices []uint) (*Handshake, error) {
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
	path := []DHPublicKey{}

	for i, leafKey := range s.leafList {
		if deleted[uint(i)] {
			continue
		}

		headData := head.derive(leafKey)
		newHead := DHNodeFromData(headData).PrivateKey

		head = newHead
		path = append(path, head.PublicKey)
	}

	indices32 := make([]uint32, len(indices))
	for i, x := range indices {
		indices32[i] = uint32(x)
	}

	abstractIdentities, err := s.identityTree.Leaves()
	if err != nil {
		return nil, err
	}

	identities, err := NewMerklePath(abstractIdentities)
	if err != nil {
		return nil, err
	}

	delete := &Delete{
		Deleted:    indices32,
		Path:       path,
		Leaves:     s.leafList,
		Identities: identities,
	}

	return s.sign(delete)
}

///
/// Functions to handle handshake messages
///

func (s *State) HandleUserAdd(signedUserAdd *Handshake) error {
	// TODO Verify that the new identity tree is a successor to the old one
	newIdentityRoot, err := signedUserAdd.IdentityRoot()
	if err != nil {
		return err
	}

	// Verify the UserAdd and GroupPreKey against the new root (since the signer is presumably not in the group)
	if err := signedUserAdd.Verify(newIdentityRoot); err != nil {
		return err
	}

	userAdd, ok := signedUserAdd.Body.(*UserAdd)
	if !ok {
		return fmt.Errorf("HandleUserAdd was not provided with a UserAdd message")
	}

	// Update ratchet tree
	addPath := make([]Node, len(userAdd.AddPath))
	for i, n := range userAdd.AddPath {
		addPath[i] = DHNodeFromPublicKey(n)
	}
	err = s.ratchetTree.AddWithPath(addPath)

	// Update other state
	identityKey := signedUserAdd.IdentityKey
	leafKey := userAdd.AddPath[len(userAdd.AddPath)-1]

	return s.addToSymmetricState(identityKey, leafKey)
}

func (s *State) HandleGroupAdd(signedGroupAdd *Handshake) error {
	err := s.verifyForCurrentRoster(signedGroupAdd)
	if err != nil {
		return err
	}

	groupAdd, ok := signedGroupAdd.Body.(*GroupAdd)
	if !ok {
		return fmt.Errorf("HandleGroupAdd was not provided with a GroupAdd message")
	}

	if err = groupAdd.PreKey.Verify(); err != nil {
		return err
	}

	preKey := groupAdd.PreKey.PreKey
	identityKey := groupAdd.PreKey.IdentityKey

	// Derive the new leaf and add it to the ratchet tree
	leafData := s.updateKey.derive(preKey)
	leafKey := DHNodeFromData(leafData).PrivateKey

	err = s.ratchetTree.Add(DHNodeFromPrivateKey(leafKey))
	if err != nil {
		return err
	}

	// Update other state
	return s.addToSymmetricState(identityKey, leafKey.PublicKey)
}

func (s *State) addToSymmetricState(identityKey SignaturePublicKey, leafKey DHPublicKey) error {
	s.epoch += 1

	err := s.identityTree.Add(NewMerkleNode(identityKey))
	if err != nil {
		return err
	}

	err = s.leafTree.Add(NewMerkleNode(leafKey))
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

	treeKey := rootNode.(*DHNode)
	epochSecret := treeKey.PrivateKey.derive(s.updateKey.PublicKey)
	s.deriveEpochKeys(epochSecret)
	return nil
}

func (s *State) HandleSelfUpdate(leafKey DHPrivateKey, signedUpdate *Handshake) error {
	err := s.handleUpdateInner(signedUpdate, &leafKey)
	if err != nil {
		return err
	}

	s.myLeafKey = leafKey
	return nil
}

func (s *State) HandleUpdate(signedUpdate *Handshake) error {
	return s.handleUpdateInner(signedUpdate, nil)
}

func (s *State) handleUpdateInner(signedUpdate *Handshake, leafKey *DHPrivateKey) error {
	err := s.verifyForCurrentRoster(signedUpdate)
	if err != nil {
		return err
	}

	update, ok := signedUpdate.Body.(*Update)
	if !ok {
		return fmt.Errorf("HandleUpdate was not provided with an Update message")
	}

	// Update leaf tree
	index := uint(signedUpdate.SignerIndex)
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
		ratchetPath[i] = DHNodeFromPublicKey(n)
	}
	if leafKey != nil {
		ratchetPath[len(ratchetPath)-1] = DHNodeFromPrivateKey(*leafKey)
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

	treeKey := rootNode.(*DHNode).Data
	epochSecret := kdf(labelEpochSecret, s.updateSecret, treeKey)
	s.deriveEpochKeys(epochSecret)
	s.epoch += 1
	return nil
}

func (s *State) importIdentities(identities MerklePath) error {
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

func (s *State) importLeaves(leafKeys DHPath) error {
	leaves := make([]Node, len(leafKeys))
	for i, leafKey := range leafKeys {
		leaves[i] = NewMerkleNode(leafKey)
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

func (s *State) HandleDelete(signedDelete *Handshake) error {
	err := s.verifyForCurrentRoster(signedDelete)
	if err != nil {
		return err
	}

	delete, ok := signedDelete.Body.(*Delete)
	if !ok {
		return fmt.Errorf("HandleDelete was not provided with a Delete message")
	}

	deleted := map[uint]bool{}
	for _, i := range delete.Deleted {
		deleted[uint(i)] = true
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
			head := DHNodeFromData(headData).PrivateKey
			headData = head.derive(leafKey)
		}
	}

	// Replace the delelted nodes with the delete key in the ratchet tree
	// Replace the deleted nodes with empty nodes in the identity tree
	emptyNode := MerkleNode{emptyMerkleLeaf()}
	deleteNode := DHNodeFromPublicKey(s.deleteKey.PublicKey)
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
