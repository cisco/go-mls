package mls

import (
	"testing"

	syntax "github.com/cisco/go-tls-syntax"
	"github.com/stretchr/testify/require"
)

const ExtensionTypeTwoByte ExtensionType = 0xffff

type TwoByteExtension [2]byte

func (ne TwoByteExtension) Type() ExtensionType {
	return ExtensionTypeTwoByte
}

func TestExtensionList(t *testing.T) {
	// Add an extension to the list
	extBody1 := &TwoByteExtension{0xFF, 0xFE}
	extBody1Data := unhex("FFFE")
	el := NewExtensionList()
	err := el.Add(extBody1)
	require.Nil(t, err)
	require.Equal(t, len(el.Entries), 1)
	require.Equal(t, el.Entries[0].ExtensionType, extBody1.Type())
	require.Equal(t, el.Entries[0].ExtensionData, extBody1Data)

	// Verify that Has() returns the expected values
	require.True(t, el.Has(ExtensionTypeTwoByte))
	require.False(t, el.Has(ExtensionTypeSupportedVersions))

	// Verify that adding again replaces the first
	extBody2 := &TwoByteExtension{0xFD, 0xFC}
	extBody2Data := unhex("FDFC")
	err = el.Add(extBody2)
	require.Nil(t, err)
	require.Equal(t, len(el.Entries), 1)
	require.Equal(t, el.Entries[0].ExtensionType, extBody2.Type())
	require.Equal(t, el.Entries[0].ExtensionData, extBody2Data)

	// Verify that the body can be retrieved
	extBody3 := new(TwoByteExtension)
	found, err := el.Find(extBody3)
	require.True(t, found)
	require.Nil(t, err)
	require.Equal(t, extBody3, extBody2)

	// Verify that an error is returned if the extension body doesn't consume all
	// of the data in the extension
	el.Entries[0].ExtensionData = append(el.Entries[0].ExtensionData, 0x00)
	found, err = el.Find(extBody3)
	require.True(t, found)
	require.Error(t, err)

	// Verify that unknown extension are reported correctly
	extBody4 := new(ParentHashExtension)
	found, err = el.Find(extBody4)
	require.False(t, found)
	require.Nil(t, err)
}

type ExtensionTestCase struct {
	extensionType ExtensionType
	blank         ExtensionBody
	unmarshaled   ExtensionBody
	marshaledHex  string
}

func (etc ExtensionTestCase) run(t *testing.T) {
	marshaled := unhex(etc.marshaledHex)

	// Test extension type
	require.Equal(t, etc.unmarshaled.Type(), etc.extensionType)

	// Test successful marshal
	out, err := syntax.Marshal(etc.unmarshaled)
	require.Nil(t, err)
	require.Equal(t, marshaled, out)

	// Test successful unmarshal
	read, err := syntax.Unmarshal(marshaled, etc.blank)
	require.Nil(t, err)
	require.Equal(t, etc.blank, etc.unmarshaled)
	require.Equal(t, read, len(marshaled))
}

var (
	lifetimeExtension = LifetimeExtension{NotBefore: 0, NotAfter: 0xA0A0A0A0A0A0A0A0}
)

var validExtensionTestCases = map[string]ExtensionTestCase{
	"SupportedVersions": {
		extensionType: ExtensionTypeSupportedVersions,
		blank:         new(SupportedVersionsExtension),
		unmarshaled:   &SupportedVersionsExtension{[]ProtocolVersion{ProtocolVersionMLS10}},
		marshaledHex:  "0100",
	},
	"SupportedCiphersuites": {
		extensionType: ExtensionTypeSupportedCipherSuites,
		blank:         new(SupportedCipherSuitesExtension),
		unmarshaled: &SupportedCipherSuitesExtension{[]CipherSuite{
			X25519_AES128GCM_SHA256_Ed25519,
			P256_AES128GCM_SHA256_P256,
		}},
		marshaledHex: "0400010002",
	},
	"Lifetime": {
		extensionType: ExtensionTypeLifetime,
		blank:         new(LifetimeExtension),
		unmarshaled:   &lifetimeExtension,
		marshaledHex:  "0000000000000000a0a0a0a0a0a0a0a0",
	},
	"ParentHash": {
		extensionType: ExtensionTypeParentHash,
		blank:         new(ParentHashExtension),
		unmarshaled:   &ParentHashExtension{[]byte{0x00, 0x01, 0x02, 0x03}},
		marshaledHex:  "0400010203",
	},
}

func TestExtensionBodyMarshalUnmarshal(t *testing.T) {
	for name, test := range validExtensionTestCases {
		t.Run(name, test.run)
	}
}
