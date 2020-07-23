package mls

import (
	"bytes"
	"fmt"
)

//
//Tuple type definition
//
type Tuple struct {
	data  []byte `tls:"head=1"`
	state *State
}

//
//Session type definition
//
type Session struct {
	CurrentEpoch     Epoch            `tls:"omit"`
	EncryptHandshake bool             `tls:"omit"`
	OutboundCache    Tuple            `tls:"omit"`
	sessionState     map[Epoch]*State `tls:"omit"`
}

//first attempt in go.  Neet to add error checking and test code

func startSession(groupID []byte, myCIKs []ClientInitKey, otherCIKs []ClientInitKey, initSecret []byte) (*Session, *Welcome, error) {

	welcome, state, err := negotiateWithPeer(groupID, myCIKs, otherCIKs, initSecret)

	if err != nil {

		return nil, nil, err
	}

	tup := &Tuple{

		data:  make([]byte, 1),
		state: state,
	}
	sess := &Session{
		CurrentEpoch:     state.Epoch,
		EncryptHandshake: false,
		OutboundCache:    *tup,
		sessionState:     make(map[Epoch]*State),
	}

	sess.addState(0, state)

	return sess, welcome, err
}

func joinSession(CIKs []ClientInitKey, welcome Welcome) (*Session, error) {

	next, err := newJoinedState(CIKs, welcome)

	if err != nil {

		return nil, err

	}

	tup := &Tuple{

		data:  make([]byte, 1),
		state: next,
	}

	sess := &Session{
		CurrentEpoch:     next.Epoch,
		EncryptHandshake: false,
		OutboundCache:    *tup,
		sessionState:     map[Epoch]*State{next.Epoch: next},
	}

	sess.addState(0, next)

	return sess, err
}

func (s *Session) encryptHandshake(enabled bool) {
	s.EncryptHandshake = enabled
}

func (s *Session) add(addSecret []byte, CIK ClientInitKey) (*Welcome, []byte) {

	proposal := s.currentState().add(CIK)

	return s.commitAndCache(addSecret, proposal)

}

func (s *Session) update(leafSecret []byte) []byte {

	proposal := s.currentState().update(leafSecret)

	_, data := s.commitAndCache(leafSecret, proposal)

	return data

}

func (s *Session) remove(evictSecret []byte, index uint32) []byte {

	proposal := s.currentState().remove(leafIndex(index))

	_, data := s.commitAndCache(evictSecret, proposal)

	return data

}

func (s *Session) handle(handshakeData []byte) {

	state := s.currentState()
	var proposal, commit *MLSPlaintext
	handShakeDataStream := NewReadStream(handshakeData)

	if s.EncryptHandshake {

		encProposal := new(MLSCiphertext)
		encCommit := new(MLSCiphertext)

		handShakeDataStream.ReadAll(encProposal, encCommit)

		proposal, _ = state.decrypt(encProposal)
		commit, _ = state.decrypt(encCommit)

	} else {

		proposal = new(MLSPlaintext)
		commit = new(MLSPlaintext)

		handShakeDataStream.Read(proposal)
		handShakeDataStream.Read(commit)

		//fmt.Println(byteR1, byteR2)
		//handShakeDataStream.Read(commit)
		//handShakeDataStream.ReadAll(proposal,commit)

	}

	if proposal.Sender == state.Index {

		if s.OutboundCache.data == nil {

			fmt.Printf("%s", fmt.Errorf("Received from self without sending"))

		}

		message := s.OutboundCache.data
		nextsessionState := s.OutboundCache.state

		if !bytes.Equal(message, handshakeData) {

			fmt.Printf("%s", fmt.Errorf("Received different own message"))

		}

		s.addState(proposal.Epoch, nextsessionState)
		s.OutboundCache.data = nil
		return
	}

	state.handle(proposal)
	next, _ := state.handle(commit)

	if next == nil {

		fmt.Printf("%s", fmt.Errorf("Commit failed to produce a new state"))

	}

	s.addState(commit.Epoch, next)

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

	if v, cond := s.sessionState[ciphertextObject.Epoch]; !cond {

		panic(fmt.Errorf("mls.session: No state available to decrypt ciphertext: %v", v))

	}

	state := s.sessionState[ciphertextObject.Epoch]
	val, err := state.unprotect(&ciphertextObject)

	if err != nil {
		return nil
	}
	return val

}

func (s *Session) commitAndCache(secret []byte, proposal *MLSPlaintext) (*Welcome, []byte) {

	state := s.currentState()
	state.handle(proposal)
	commit, welcome, newState, err := state.commit(secret)
	if err != nil {
		return nil, nil
	}

	w := NewWriteStream()

	if s.EncryptHandshake {
		encProposal, _ := state.encrypt(proposal)
		encCommit, _ := state.encrypt(commit)
		w.WriteAll(encProposal, encCommit)
	} else {
		w.Write(proposal)
		w.Write(commit)
		//w.WriteAll(proposal, commit)

	}

	//var tproposal, tcommit *MLSPlaintext

	//test := dup(w.Data())

	//fmt.Printf("%x\n", test)

	//handShakeDataStream := NewReadStream(test)

	//tproposal = new(MLSPlaintext)
	//tcommit = new(MLSPlaintext)

	//tbyteR1, err1 := handShakeDataStream.Read(tproposal)
	//tbyteR2, err2 := handShakeDataStream.Read(tcommit)

	//println(err1, err2, tproposal, tcommit, tbyteR1, tbyteR2)

	msg := w.Data()

	s.OutboundCache.data = msg
	s.OutboundCache.state = newState

	return welcome, msg

}

func makeInitKey(initSecret []byte) {

}

func (s *Session) addState(priorEpoch Epoch, state *State) {

	s.sessionState[state.Epoch] = state

	if priorEpoch == s.CurrentEpoch || len(s.sessionState) == 1 {

		s.CurrentEpoch = state.Epoch
	}

}

func (s *Session) currentState() *State {

	if v, cond := s.sessionState[s.CurrentEpoch]; !cond {

		fmt.Printf("%s", fmt.Errorf("mls.session: No state available for current epoch: %v", v))
	}

	return s.sessionState[s.CurrentEpoch]

}

func (s *Session) evaluateEquals(sess *Session) bool {
	type Tuple struct {
		data  []byte `tls:"head=1"`
		state State
	}

	//
	//Session type definition
	//
	type Session struct {
		CurrentEpoch     Epoch            `tls:"omit"`
		EncryptHandshake bool             `tls:"omit"`
		OutboundCache    Tuple            `tls:"omit"`
		sessionState     map[Epoch]*State `tls:"omit"`
	}

	if s.CurrentEpoch != sess.CurrentEpoch || s.EncryptHandshake != sess.EncryptHandshake {
		return false
	}

	for epoch, state := range s.sessionState {
		otherState, ok := sess.sessionState[epoch]
		if !ok {
			continue
		}

		if !state.Equals(*otherState) {
			return false
		}
	}

	return true

}