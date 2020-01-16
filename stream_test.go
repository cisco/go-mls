package mls

import (
	"testing"
)

type streamTestVec struct {
	Data []byte `tls:"head=2"`
}

var streamTestInputs = struct {
	val1    uint8
	val2    uint16
	val3    streamTestVec
	val4    uint32
	encoded []byte
}{
	0xA0,
	0xB0B0,
	streamTestVec{[]byte{0xC0, 0xC0, 0xC0}},
	0xD0D0D0D0,
	unhex("A0B0B00003C0C0C0D0D0D0D0"),
}

func TestWriteStream(t *testing.T) {
	w := NewWriteStream()

	err := w.Write(streamTestInputs.val1)
	assertNotError(t, err, "Error writing to stream")

	err = w.Write(streamTestInputs.val2)
	assertNotError(t, err, "Error writing to stream")

	err = w.Write(streamTestInputs.val3)
	assertNotError(t, err, "Error writing to stream")

	err = w.Write(streamTestInputs.val4)
	assertNotError(t, err, "Error writing to stream")

	encoded := w.Data()
	assertByteEquals(t, encoded, streamTestInputs.encoded)

	w = NewWriteStream()
	err = w.WriteAll(streamTestInputs.val1, streamTestInputs.val2,
		streamTestInputs.val3, streamTestInputs.val4)
	assertNotError(t, err, "Error in WriteAll")
	assertByteEquals(t, w.Data(), streamTestInputs.encoded)
}

func TestReadStream(t *testing.T) {
	r := NewReadStream(streamTestInputs.encoded)

	var val1 uint8
	read, err := r.Read(&val1)
	assertNotError(t, err, "Error reading from stream")
	assertEquals(t, read, 1)
	assertDeepEquals(t, val1, streamTestInputs.val1)

	var val2 uint16
	read, err = r.Read(&val2)
	assertNotError(t, err, "Error reading from stream")
	assertEquals(t, read, 2)
	assertDeepEquals(t, val2, streamTestInputs.val2)

	var val3 streamTestVec
	read, err = r.Read(&val3)
	assertNotError(t, err, "Error reading from stream")
	assertEquals(t, read, 5)
	assertDeepEquals(t, val3, streamTestInputs.val3)

	var val4 uint32
	read, err = r.Read(&val4)
	assertNotError(t, err, "Error reading from stream")
	assertEquals(t, read, 4)
	assertDeepEquals(t, val4, streamTestInputs.val4)

	r = NewReadStream(streamTestInputs.encoded)
	read, err = r.ReadAll(&val1, &val2, &val3, &val4)
	assertNotError(t, err, "Error in ReadAll")
	assertEquals(t, read, 1+2+5+4)
	assertDeepEquals(t, val1, streamTestInputs.val1)
	assertDeepEquals(t, val2, streamTestInputs.val2)
	assertDeepEquals(t, val3, streamTestInputs.val3)
	assertDeepEquals(t, val4, streamTestInputs.val4)
}
