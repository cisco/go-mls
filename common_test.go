package mls

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
)

type TestEnum uint8

var (
	TestEnumInvalid TestEnum = 0xFF
	TestEnumVal0    TestEnum = 0
	TestEnumVal1    TestEnum = 1
)

func TestValidateEnum(t *testing.T) {
	err := validateEnum(TestEnumVal0, TestEnumVal0, TestEnumVal1)
	require.Nil(t, err)

	err = validateEnum(TestEnumInvalid, TestEnumVal0, TestEnumVal1)
	require.Error(t, err)
}

//////////

func unhex(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}
