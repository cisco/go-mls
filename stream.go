package mls

import "github.com/bifurcation/mint/syntax"

// TODO(suhasHere): move this file to mint/syntax once it looks good for its purpose

///
/// Write Stream
///

type WriteStream struct {
	buffer []byte
}

func NewWriteStream() *WriteStream {
	return &WriteStream{}
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

func (s *WriteStream) WriteAll(vals ...interface{}) error {
	for _, val := range vals {
		err := s.Write(val)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *WriteStream) Append(b []byte) error {
	s.buffer = append(s.buffer, b...)
	return nil
}

///
/// ReadStream
///

type ReadStream struct {
	buffer []byte
	cursor int
}

func NewReadStream(data []byte) *ReadStream {
	return &ReadStream{data, 0}
}

func (s *ReadStream) Read(val interface{}) (int, error) {
	read, err := syntax.Unmarshal(s.buffer[s.cursor:], val)
	if err != nil {
		return 0, err
	}

	s.cursor += read
	return read, nil
}

func (s *ReadStream) ReadAll(vals ...interface{}) (int, error) {
	totalRead := 0
	for _, val := range vals {
		read, err := s.Read(val)
		if err != nil {
			return 0, err
		}
		totalRead += read
	}
	return totalRead, nil
}

func (s *ReadStream) Consumed() int {
	return s.cursor
}
