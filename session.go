package mls

import (
	"bytes"
	"fmt"
)

type Session struct {
	State                map[Epoch]*State
	CurrentEpoch         Epoch
	EncryptHandshake     bool
	OutboundMessageCache []byte
	OutboundStateCache   *State
}

func StartSession(groupID []byte, myCIKs, otherCIKs []ClientInitKey, initialSecret []byte) (*Session, *Welcome, error) {
	welcome, state, err := negotiateWithPeer(groupID, myCIKs, otherCIKs, initialSecret)
	if err != nil {
		return nil, nil, err
	}

	session := &Session{
		State:        map[Epoch]*State{state.Epoch: state},
		CurrentEpoch: state.Epoch,
	}
	return session, welcome, nil
}

func JoinSession(myCIKs []ClientInitKey, welcome Welcome) (*Session, error) {
	state, err := newJoinedState(myCIKs, welcome)
	if err != nil {
		return nil, err
	}

	session := &Session{
		State:        map[Epoch]*State{state.Epoch: state},
		CurrentEpoch: state.Epoch,
	}
	return session, nil
}

func (s Session) Equals(other *Session) bool {
	if s.EncryptHandshake != other.EncryptHandshake {
		return false
	}

	if s.CurrentEpoch != other.CurrentEpoch {
		return false
	}

	for epoch, state := range s.State {
		otherState, ok := other.State[epoch]
		if !ok {
			continue
		}

		if !state.Equals(*otherState) {
			return false
		}
	}

	return true
}

func (s *Session) addState(priorEpoch Epoch, state *State) {
	s.State[state.Epoch] = state
	if priorEpoch == s.CurrentEpoch {
		s.CurrentEpoch = state.Epoch
	}
}

func (s Session) currentState() *State {
	return s.State[s.CurrentEpoch]
}

func (s Session) Index() leafIndex {
	return s.currentState().Index
}

func (s *Session) commitAndCache(commitSecret []byte, proposal *MLSPlaintext) (*Welcome, []byte, error) {
	state := s.currentState()
	_, err := state.handle(proposal)
	if err != nil {
		return nil, nil, err
	}

	commit, welcome, newState, err := state.commit(commitSecret)
	if err != nil {
		return nil, nil, err
	}

	w := NewWriteStream()
	if s.EncryptHandshake {
		encProposal, err2 := state.encrypt(proposal)
		if err2 != nil {
			return nil, nil, err
		}

		encCommit, err2 := state.encrypt(proposal)
		if err2 != nil {
			return nil, nil, err
		}

		err = w.WriteAll(encProposal, encCommit)
	} else {
		err = w.WriteAll(proposal, commit)
	}
	if err != nil {
		return nil, nil, err
	}
	msg := w.Data()

	s.OutboundMessageCache = msg
	s.OutboundStateCache = newState
	return welcome, msg, nil
}

func (s *Session) Add(addSecret []byte, cik ClientInitKey) (*Welcome, []byte, error) {
	proposal := s.currentState().add(cik)
	return s.commitAndCache(addSecret, proposal)
}

func (s *Session) Update(leafSecret []byte) ([]byte, error) {
	proposal := s.currentState().update(leafSecret)
	_, msg, err := s.commitAndCache(leafSecret, proposal)
	return msg, err
}

func (s *Session) Remove(evictSecret []byte, target leafIndex) ([]byte, error) {
	proposal := s.currentState().remove(target)
	_, msg, err := s.commitAndCache(evictSecret, proposal)
	return msg, err
}

func (s *Session) Handle(message []byte) error {
	state := s.currentState()

	var proposal, commit *MLSPlaintext
	r := NewReadStream(message)
	if s.EncryptHandshake {
		encProposal := new(MLSCiphertext)
		encCommit := new(MLSCiphertext)
		_, err := r.ReadAll(encProposal, encCommit)
		if err != nil {
			return err
		}

		proposal, err = state.decrypt(encProposal)
		if err != nil {
			return err
		}

		commit, err = state.decrypt(encCommit)
		if err != nil {
			panic(err)
			return err
		}
	} else {
		proposal = new(MLSPlaintext)
		commit = new(MLSPlaintext)
		_, err := r.ReadAll(proposal)
		if err != nil {
			panic(err)
			return err
		}
	}

	if proposal.Sender == state.Index {
		if s.OutboundMessageCache == nil || s.OutboundStateCache == nil {
			return fmt.Errorf("Received from self without sending")
		}

		if !bytes.Equal(message, s.OutboundMessageCache) {
			return fmt.Errorf("Received different own message")
		}

		s.addState(proposal.Epoch, s.OutboundStateCache)
		s.OutboundMessageCache = nil
		s.OutboundStateCache = nil
		return nil
	}

	_, err := state.handle(proposal)
	if err != nil {
		return err
	}

	next, err := state.handle(commit)
	if err != nil {
		return err
	}
	if next == nil {
		return fmt.Errorf("Commit failed to produce a new state")
	}
	s.addState(commit.Epoch, next)
	return nil
}

func (s *Session) Protect(plaintext []byte) ([]byte, error) {
	// TODO
	return nil, nil
}

func (s *Session) Unprotect(ciphertext []byte) ([]byte, error) {
	// TODO
	return nil, nil
}
