package mls

///
/// GroupContext
///
type GroupContext struct {
	GroupID                 []byte `tls:"head=1"`
	Epoch                   Epoch
	TreeHash                []byte `tls:"head=1"`
	ConfirmedTranscriptHash []byte `tls:"head=1"`
}

// TODO: Define this for real, probably in key-schedule.go
type KeyScheduleEpoch struct{}

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
	Keys KeyScheduleEpoch

	// Per-participant state
	Index        leafIndex
	IdentityPriv SignaturePrivateKey

	// Cache of proposals and update secrets
	PendingProposals []MLSPlaintext
	UpdateSecrets    map[ProposalID][]byte
}

func newEmptyState(groupID []byte, cs CipherSuite, leafPriv HPKEPrivateKey, cred Credential) (*State, error) {
	// TODO
	return nil, nil
}

func newJoinedState(ciks []ClientInitKey, welcome Welcome) (*State, error) {
	// TODO
	return nil, nil
}

func negotiateWithPeer(groupID []byte, myCIKs, otherCIKs []ClientInitKey, commitSecret []byte) (*Welcome, *State, error) {
	// TODO
	return nil, nil, nil
}

func (s State) add(cik ClientInitKey) (*MLSPlaintext, error) {
	// TODO
	return nil, nil
}

func (s *State) update(leafSecret []byte) (*MLSPlaintext, error) {
	// TODO
	return nil, nil
}

func (s State) remove(removed leafIndex) (*MLSPlaintext, error) {
	// TODO
	return nil, nil
}

func (s State) commit(leafSecret []byte) (*MLSPlaintext, *Welcome, *State, error) {
	// TODO
	return nil, nil, nil, nil
}

func (s State) handle(pt *MLSPlaintext) (*State, error) {
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
	return nil
}
