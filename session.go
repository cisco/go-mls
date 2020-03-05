package mls

import (
	"bytes"
	"fmt"
)

type Tuple struct {
	data  []byte
	state State
}

type Session struct {
	_current_epoch     Epoch
	_encrypt_handshake bool
	_outbound_cache    Tuple
	_state             map[Epoch]*State
}

func (s *Session) start(groupID []byte, myCIKs []ClientInitKey, otherCIKs []ClientInitKey, initSecret []byte) (*Session, *Welcome, error) {

	welcome, state, err := negotiateWithPeer(groupID, myCIKs, otherCIKs, initSecret)
	sess := &Session{
		_current_epoch:     0,
		_encrypt_handshake: false,
	}

	s.add_state(0, state)

	return sess, welcome, err
}

func (s *Session) join(CIKs []ClientInitKey, welcome Welcome) (*Session, error) {

	sess := &Session{
		_current_epoch:     0,
		_encrypt_handshake: false,
	}

	next, err := newJoinedState(CIKs, welcome)

	s.add_state(0, next)

	return sess, err
}

func (s *Session) encrypt_handshake(enabled bool) {
	s._encrypt_handshake = enabled
}

func (s *Session) add(addSecret []byte, CIK ClientInitKey) (*Welcome, []byte) {

	proposal := s.currentState().add(CIK)

	return s.commit_and_cache(addSecret, proposal)

}

func (s *Session) update(leafSecret []byte) []byte {

	proposal := s.currentState().update(leafSecret)

	_, data := s.commit_and_cache(leafSecret, proposal)

	return data

}

func (s *Session) remove(evictSecret []byte, index uint32) []byte {

	proposal := s.currentState().remove(leafIndex(index))

	_, data := s.commit_and_cache(evictSecret, proposal)

	return data

}

func (s *Session) handle(handshakeData []byte) {

	state := s.currentState()
	var proposal *MLSPlaintext
	var commit *MLSPlaintext

	handShakeDataStream := NewReadStream(handshakeData)

	if s._encrypt_handshake {

		var enc_proposal MLSCiphertext
		var enc_commit MLSCiphertext

		handShakeDataStream.ReadAll(&enc_proposal, &enc_commit)

		proposal, _ = state.decrypt(&enc_proposal)
		commit, _ = state.decrypt(&enc_commit)

	} else {

		handShakeDataStream.ReadAll(&proposal, &commit)

	}

	if proposal.Sender == state.Index {

		if s._outbound_cache.data == nil {

			fmt.Printf("%s", fmt.Errorf("Received from self without sending"))

		}

		message := s._outbound_cache.data
		next_state := s._outbound_cache.state

		if bytes.Compare(message, handshakeData) != 0 {

			fmt.Printf("%s", fmt.Errorf("Received different own message"))

		}

		s.add_state(proposal.Epoch, &next_state)
		s._outbound_cache.data = nil

		return
	}

	state.handle(proposal)
	next, _ := state.handle(commit)

	if next == nil {

		fmt.Printf("%s", fmt.Errorf("Commit failed to produce a new state"))

	}

	s.add_state(commit.Epoch, next)

}

func (s *Session) protect(plaintext []byte) []byte {
	ctWriteStream := NewWriteStream()

	ciphertext, _ := s.currentState().protect(plaintext)
	ctWriteStream.Write(ciphertext)

	return ctWriteStream.Data()
}

func (s *Session) unprotect(ciphertext []byte) []byte {
	var ciphertextObject MLSCiphertext

	ctDataStream := NewReadStream(ciphertext)
	ctDataStream.Read(&ciphertextObject)

	if v, cond := s._state[ciphertextObject.Epoch]; !cond {

		fmt.Printf("%s", fmt.Errorf("mls.session: No state available to decrypt ciphertext: %v", v))

	}

	state := s._state[ciphertextObject.Epoch]
	val, _ := state.unprotect(&ciphertextObject)
	return val

}

func (s *Session) commit_and_cache(secret []byte, proposal *MLSPlaintext) (*Welcome, []byte) {
	state := s.currentState()

	state.handle(proposal)

	commit, welcome, _, _ := state.commit(secret)

	w := NewWriteStream()

	if s._encrypt_handshake {
		enc_proposal, _ := state.encrypt(proposal)
		enc_commit, _ := state.encrypt(commit)
		w.WriteAll(enc_proposal, enc_commit)
	} else {

		w.WriteAll(proposal, commit)

	}

	msg := w.Data()

	s._outbound_cache.data = msg
	s._outbound_cache.state = *state

	return welcome, msg

}

func make_init_key(init_secret []byte) {

}

func (s *Session) add_state(prior_epoch Epoch, state *State) {

	s._state[state.Epoch] = state

	if prior_epoch == s._current_epoch || len(s._state) == 1 {

		s._current_epoch = state.Epoch
	}

}

func (s *Session) currentState() *State {

	if v, cond := s._state[s._current_epoch]; !cond {

		fmt.Printf("%s", fmt.Errorf("mls.session: No state available for current epoch: %v", v))
	}
	val, _ := (s._state[s._current_epoch])

	return val

}
