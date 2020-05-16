package mls

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cisco/go-tls-syntax"
	"github.com/stretchr/testify/require"
)

// XXX(rlb): Uncomment this to see a graphical illustration of how the
// tree-based key derivation works
/*
func TestTreeBaseKeySource(t *testing.T) {
	size := LeafCount(11)
	root := unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	tbks := newTreeBaseKeySource(P256_SHA256_AES128GCM, size, root)
	for i := LeafIndex(0); i < LeafIndex(size); i += 1 {
		tbks.Get(i)
		tbks.dump()
	}
}
*/

// XXX(rlb): This is a very loose check, just exercising the code and verifying
// that it doesnt panic and produces outputs that are the right size.  We should
// do actual interop testing.  There's not much between here and there.
func TestKeySchedule(t *testing.T) {
	suite := P256_AES128GCM_SHA256_P256
	secretSize := suite.Constants().SecretSize
	keySize := suite.Constants().KeySize
	nonceSize := suite.Constants().NonceSize

	size1 := LeafCount(5)
	epochSecret1 := unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	context1 := []byte("first")

	size2 := LeafCount(11)
	psk2 := []byte("psk")
	commitSecret2 := unhex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
	context2 := []byte("second")

	exportSize := 128
	targetGeneration := uint32(3)

	checkEpoch := func(epoch *keyScheduleEpoch, size LeafCount) {
		require.Equal(t, epoch.Suite, suite)
		require.Equal(t, len(epoch.EpochSecret), secretSize)
		require.Equal(t, len(epoch.SenderDataSecret), secretSize)
		require.Equal(t, len(epoch.SenderDataKey), keySize)
		require.Equal(t, len(epoch.HandshakeSecret), secretSize)
		require.Equal(t, len(epoch.ApplicationSecret), secretSize)
		require.Equal(t, len(epoch.ExporterSecret), secretSize)
		require.Equal(t, len(epoch.ConfirmationKey), secretSize)
		require.Equal(t, len(epoch.InitSecret), secretSize)
		require.NotNil(t, epoch.HandshakeKeys)
		require.NotNil(t, epoch.HandshakeKeys)

		exportedKey := epoch.Export("test", []byte{0, 1, 2, 3}, exportSize)
		require.Equal(t, len(exportedKey), exportSize)

		for i := LeafIndex(0); i < LeafIndex(size); i += 1 {
			// Test successful generation
			hs, err := epoch.HandshakeKeys.Get(i, targetGeneration)
			require.Nil(t, err)
			require.Equal(t, len(hs.Key), keySize)
			require.Equal(t, len(hs.Nonce), nonceSize)

			app, err := epoch.ApplicationKeys.Get(i, targetGeneration)
			require.Nil(t, err)
			require.Equal(t, len(app.Key), keySize)
			require.Equal(t, len(app.Nonce), nonceSize)

			epoch.HandshakeKeys.Erase(i, targetGeneration)
			epoch.ApplicationKeys.Erase(i, targetGeneration)

			// Test forward secrecy
			_, err = epoch.HandshakeKeys.Get(i, targetGeneration)
			require.Error(t, err)

			_, err = epoch.ApplicationKeys.Get(i, targetGeneration)
			require.Error(t, err)
		}
	}

	epoch1 := newKeyScheduleEpoch(suite, size1, epochSecret1, context1)
	checkEpoch(&epoch1, size1)

	epoch2 := epoch1.Next(size2, psk2, commitSecret2, context2)
	checkEpoch(&epoch2, size2)

	// Check that marshal/unmarshal works
	epoch2m, err := syntax.Marshal(epoch2)
	require.Nil(t, err)

	var epoch2u keyScheduleEpoch
	_, err = syntax.Unmarshal(epoch2m, &epoch2u)
	require.Nil(t, err)

	epoch2u.enableKeySources()

	// Verify that the contents match (not the group key generators)
	require.Equal(t, epoch2.Suite, epoch2u.Suite)
	require.Equal(t, epoch2.EpochSecret, epoch2u.EpochSecret)
	require.Equal(t, epoch2.SenderDataSecret, epoch2u.SenderDataSecret)
	require.Equal(t, epoch2.SenderDataKey, epoch2u.SenderDataKey)
	require.Equal(t, epoch2.HandshakeSecret, epoch2u.HandshakeSecret)
	require.Equal(t, epoch2.ApplicationSecret, epoch2u.ApplicationSecret)
	require.Equal(t, epoch2.ConfirmationKey, epoch2u.ConfirmationKey)
	require.Equal(t, epoch2.InitSecret, epoch2u.InitSecret)
	require.Equal(t, epoch2.HandshakeBaseKeys, epoch2u.HandshakeBaseKeys)
	require.Equal(t, epoch2.ApplicationBaseKeys, epoch2u.ApplicationBaseKeys)
	require.Equal(t, epoch2.HandshakeRatchets, epoch2u.HandshakeRatchets)
	require.Equal(t, epoch2.ApplicationRatchets, epoch2u.ApplicationRatchets)

	// Verify that we can't get a key for the target generation (because it's
	// already consumed)
	_, err = epoch2u.HandshakeKeys.Get(0, targetGeneration)
	require.Error(t, err)

	// Verify that we can get one for the next epoch, and it's the same as the
	// original key schedule would have produced
	_, err = epoch2u.HandshakeKeys.Get(0, targetGeneration+1)
	require.Nil(t, err)
}

///
/// Vectors
///

type KsEpoch struct {
	NumMembers   LeafCount
	PSK          []byte `tls:"head=1"`
	CommitSecret []byte `tls:"head=1"`

	EpochSecret      []byte        `tls:"head=1"`
	SenderDataSecret []byte        `tls:"head=1"`
	SenderDataKey    []byte        `tls:"head=1"`
	HandshakeSecret  []byte        `tls:"head=1"`
	HandshakeKeys    []keyAndNonce `tls:"head=4"`
	AppSecret        []byte        `tls:"head=1"`
	AppKeys          []keyAndNonce `tls:"head=4"`
	ExporterSecret   []byte        `tls:"head=1"`
	ExportedSecret   []byte        `tls:"head=1"`
	ConfirmationKey  []byte        `tls:"head=1"`
	InitSecret       []byte        `tls:"head=1"`
}

type KsTestCase struct {
	CipherSuite CipherSuite
	Epochs      []KsEpoch `tls:"head=2"`
}

type KsTestVectors struct {
	NumEpochs        uint32
	TargetGeneration uint32
	ExportLabel      []byte `tls:"head=1"`
	ExportContext    []byte `tls:"head=1"`
	ExportSize       uint32
	BaseInitSecret   []byte       `tls:"head=1"`
	BaseGroupContext []byte       `tls:"head=4"`
	Cases            []KsTestCase `tls:"head=4"`
}

/// Gen and Verify
func generateKeyScheduleVectors(t *testing.T) []byte {
	var tv KsTestVectors
	suites := []CipherSuite{P256_AES128GCM_SHA256_P256}
	baseGrpCtx := GroupContext{
		GroupID:                 []byte{0xA0, 0xA0, 0xA0, 0xA0},
		Epoch:                   0,
		TreeHash:                bytes.Repeat([]byte{0xA1}, 32),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0xA2}, 32),
	}

	encCtx, err := syntax.Marshal(baseGrpCtx)
	require.Nil(t, err)
	tv.NumEpochs = 50
	tv.TargetGeneration = 3
	tv.ExportLabel = []byte("exportLabel")
	tv.ExportContext = []byte("exportContext")
	tv.ExportSize = 24
	tv.BaseInitSecret = bytes.Repeat([]byte{0xA3}, 32)
	tv.BaseGroupContext = encCtx

	for _, suite := range suites {
		var tc KsTestCase
		tc.CipherSuite = suite
		// start with the base context for epoch0
		grpCtx := baseGrpCtx
		minMembers := 5
		maxMembers := 20
		nMembers := minMembers

		var epoch keyScheduleEpoch
		epoch.Suite = suite
		epoch.InitSecret = tv.BaseInitSecret
		for i := 0; i < int(tv.NumEpochs); i++ {
			ctx, _ := syntax.Marshal(grpCtx)

			psk := []byte(fmt.Sprintf("psk @ %d", i))
			commitSecret := []byte(fmt.Sprintf("commitSecret @ %d", i))
			epoch = epoch.Next(LeafCount(nMembers), psk, commitSecret, ctx)

			var handshakeKeys []keyAndNonce
			var applicationKeys []keyAndNonce
			appSecret := dup(epoch.ApplicationSecret)
			for j := 0; j < nMembers; j++ {
				hs, _ := epoch.HandshakeKeys.Get(LeafIndex(j), tv.TargetGeneration)
				handshakeKeys = append(handshakeKeys, hs)
				as, _ := epoch.ApplicationKeys.Get(LeafIndex(j), tv.TargetGeneration)
				applicationKeys = append(applicationKeys, as)
			}

			exportedSecret := epoch.Export(string(tv.ExportLabel), tv.ExportContext, int(tv.ExportSize))

			kse := KsEpoch{
				PSK:          psk,
				CommitSecret: commitSecret,

				NumMembers:       LeafCount(nMembers),
				EpochSecret:      epoch.EpochSecret,
				SenderDataSecret: epoch.SenderDataSecret,
				SenderDataKey:    epoch.SenderDataKey,
				HandshakeSecret:  epoch.HandshakeSecret,
				HandshakeKeys:    handshakeKeys,
				AppSecret:        appSecret,
				AppKeys:          applicationKeys,
				ExporterSecret:   epoch.ExporterSecret,
				ExportedSecret:   exportedSecret,
				ConfirmationKey:  epoch.ConfirmationKey,
				InitSecret:       epoch.InitSecret,
			}

			tc.Epochs = append(tc.Epochs, kse)

			grpCtx.Epoch += 1
			nMembers = (nMembers-minMembers)%(maxMembers-minMembers) + minMembers
		}
		tv.Cases = append(tv.Cases, tc)
	}

	vec, err := syntax.Marshal(tv)
	require.Nil(t, err)
	return vec
}

func verifyKeyScheduleVectors(t *testing.T, data []byte) {
	var tv KsTestVectors
	_, err := syntax.Unmarshal(data, &tv)
	require.Nil(t, err)
	for _, tc := range tv.Cases {
		suite := tc.CipherSuite
		var grpCtx GroupContext
		_, err := syntax.Unmarshal(tv.BaseGroupContext, &grpCtx)
		require.Nil(t, err)
		var myEpoch keyScheduleEpoch
		myEpoch.Suite = suite
		myEpoch.InitSecret = tv.BaseInitSecret
		for _, epoch := range tc.Epochs {
			ctx, _ := syntax.Marshal(grpCtx)
			myEpoch = myEpoch.Next(epoch.NumMembers, epoch.PSK, epoch.CommitSecret, ctx)

			// check the secrets
			require.Equal(t, myEpoch.EpochSecret, epoch.EpochSecret)
			require.Equal(t, myEpoch.SenderDataSecret, epoch.SenderDataSecret)
			require.Equal(t, myEpoch.SenderDataKey, epoch.SenderDataKey)
			require.Equal(t, myEpoch.HandshakeSecret, epoch.HandshakeSecret)
			require.Equal(t, myEpoch.ApplicationSecret, epoch.AppSecret)
			require.Equal(t, myEpoch.ExporterSecret, epoch.ExporterSecret)
			require.Equal(t, myEpoch.ConfirmationKey, epoch.ConfirmationKey)
			require.Equal(t, myEpoch.InitSecret, epoch.InitSecret)

			// check export
			exportedSecret := myEpoch.Export(string(tv.ExportLabel), tv.ExportContext, int(tv.ExportSize))
			require.Equal(t, exportedSecret, epoch.ExportedSecret)

			// check the keys
			for i := 0; LeafCount(i) < epoch.NumMembers; i++ {
				hs, err := myEpoch.HandshakeKeys.Get(LeafIndex(i), tv.TargetGeneration)
				require.Nil(t, err)
				require.Equal(t, hs.Key, epoch.HandshakeKeys[i].Key)
				require.Equal(t, hs.Nonce, epoch.HandshakeKeys[i].Nonce)

				as, err := myEpoch.ApplicationKeys.Get(LeafIndex(i), tv.TargetGeneration)
				require.Nil(t, err)
				require.Equal(t, as.Key, epoch.AppKeys[i].Key)
				require.Equal(t, as.Nonce, epoch.AppKeys[i].Nonce)

			}
			grpCtx.Epoch += 1
		}
	}
}
