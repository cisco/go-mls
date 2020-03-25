package mls

import (
	"testing"

	"github.com/stretchr/testify/require"
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
	require.Nil(t, err)

	err = w.Write(streamTestInputs.val2)
	require.Nil(t, err)

	err = w.Write(streamTestInputs.val3)
	require.Nil(t, err)

	err = w.Write(streamTestInputs.val4)
	require.Nil(t, err)

	encoded := w.Data()
	require.Equal(t, encoded, streamTestInputs.encoded)

	w2 := NewWriteStream()
	err = w2.WriteAll(streamTestInputs.val1, streamTestInputs.val2,
		streamTestInputs.val3, streamTestInputs.val4)
	require.Nil(t, err)
	require.Equal(t, w.Data(), w2.Data())
}

func TestReadStream(t *testing.T) {
	r := NewReadStream(streamTestInputs.encoded)

	var val1 uint8
	read, err := r.Read(&val1)
	require.Nil(t, err)
	require.Equal(t, read, 1)
	require.Equal(t, val1, streamTestInputs.val1)

	var val2 uint16
	read, err = r.Read(&val2)
	require.Nil(t, err)
	require.Equal(t, read, 2)
	require.Equal(t, val2, streamTestInputs.val2)

	var val3 streamTestVec
	read, err = r.Read(&val3)
	require.Nil(t, err)
	require.Equal(t, read, 5)
	require.Equal(t, val3, streamTestInputs.val3)

	var val4 uint32
	read, err = r.Read(&val4)
	require.Nil(t, err)
	require.Equal(t, read, 4)
	require.Equal(t, val4, streamTestInputs.val4)

	var val1a uint8
	var val2a uint16
	var val3a streamTestVec
	var val4a uint32
	r2 := NewReadStream(streamTestInputs.encoded)
	read, err = r2.ReadAll(&val1a, &val2a, &val3a, &val4a)
	require.Nil(t, err)
	require.Equal(t, read, len(streamTestInputs.encoded))
	require.Equal(t, val1, val1a)
	require.Equal(t, val2, val2a)
	require.Equal(t, val3, val3a)
	require.Equal(t, val4, val4a)

}
