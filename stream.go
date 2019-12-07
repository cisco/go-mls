package mls

import "github.com/bifurcation/mint/syntax"

// TODO: move this file to mint/syntax once it looks good for its purpose

// Interface for encoding/decoding data in a peice-meal fashion

type Stream interface {
	Data() []byte
}

type StreamReader interface {
	Stream
	Read(b []byte, val interface{}) (int, error)
	ResetCursor(curor int)
}

type StreamWriter interface {
	Stream
	Write(val interface{}) error
	Append(b []byte) error
}

func NewStreamReader() StreamReader {
	return &ReadStream{}
}

func NewStreamWriter() StreamWriter {
	return &WriteStream{}
}

//// Write Stream

type WriteStream struct {
	buffer []byte
}

func (s *WriteStream) Data() []byte {
	return s.buffer
}

func (s *WriteStream) Write(val interface{}) error {
	enc, err := syntax.Marshal(val)
	if err != nil {
		return err
	}
	s.buffer = append(s.buffer, enc...)
	return nil
}

func (s *WriteStream) Append(b []byte) error {
	s.buffer = append(s.buffer, b...)
	return nil
}

//// ReadStream

type ReadStream struct {
	buffer []byte
	cursor int
}

func (s *ReadStream) Read(enc []byte, val interface{}) (int, error) {
	read, err := syntax.Unmarshal(enc[s.cursor:], val)
	s.cursor += read
	if err != nil {
		return 0, err
	}
	return s.cursor, nil
}

func (s *ReadStream) ResetCursor(cursor int) {
	s.cursor = cursor
}

func (s *ReadStream) Data() []byte {
	return s.buffer
}
