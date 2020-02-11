package mls

import (
	"bytes"
	"github.com/bifurcation/mint/syntax"
	"testing"
)

// XXX(rlb): Uncomment this to see a graphical illustration of how the
// tree-based key derivation works
/*
func TestTreeBaseKeySource(t *testing.T) {
	size := leafCount(11)
	root := unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	tbks := newTreeBaseKeySource(P256_SHA256_AES128GCM, size, root)
	for i := leafIndex(0); i < leafIndex(size); i += 1 {
		tbks.Get(i)
		tbks.dump()
	}
}
*/

// XXX(rlb): This is a very loose check, just exercising the code and verifying
// that it doesnt panic and produces outputs that are the right size.  We should
// do actual interop testing.  There's not much between here and there.
func TestKeySchedule(t *testing.T) {
	suite := P256_SHA256_AES128GCM
	secretSize := suite.constants().SecretSize
	keySize := suite.constants().KeySize
	nonceSize := suite.constants().NonceSize

	size1 := leafCount(5)
	epochSecret1 := unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	context1 := []byte("first")

	size2 := leafCount(11)
	commitSecret2 := unhex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
	context2 := []byte("second")

	targetGeneration := uint32(3)

	checkEpoch := func(epoch *keyScheduleEpoch, size leafCount) {
		assertEquals(t, epoch.Suite, suite)
		assertEquals(t, len(epoch.EpochSecret), secretSize)
		assertEquals(t, len(epoch.SenderDataSecret), secretSize)
		assertEquals(t, len(epoch.SenderDataKey), keySize)
		assertEquals(t, len(epoch.HandshakeSecret), secretSize)
		assertEquals(t, len(epoch.ApplicationSecret), secretSize)
		assertEquals(t, len(epoch.ConfirmationKey), secretSize)
		assertEquals(t, len(epoch.InitSecret), secretSize)
		assertNotNil(t, epoch.HandshakeKeys, "Missing handshake keys")
		assertNotNil(t, epoch.HandshakeKeys, "Missing application keys")

		for i := leafIndex(0); i < leafIndex(size); i += 1 {
			// Test successful generation
			hs, err := epoch.HandshakeKeys.Get(i, targetGeneration)
			assertNotError(t, err, "Error in handshake key generation")
			assertEquals(t, len(hs.Key), keySize)
			assertEquals(t, len(hs.Nonce), nonceSize)

			app, err := epoch.ApplicationKeys.Get(i, targetGeneration)
			assertNotError(t, err, "Error in handshake key generation")
			assertEquals(t, len(app.Key), keySize)
			assertEquals(t, len(app.Nonce), nonceSize)

			epoch.HandshakeKeys.Erase(i, targetGeneration)
			epoch.ApplicationKeys.Erase(i, targetGeneration)

			// Test forward secrecy
			_, err = epoch.HandshakeKeys.Get(i, targetGeneration)
			assertError(t, err, "Reused handshake key")

			_, err = epoch.ApplicationKeys.Get(i, targetGeneration)
			assertError(t, err, "Reused handshake key")
		}
	}

	epoch1 := newKeyScheduleEpoch(suite, size1, epochSecret1, context1)
	checkEpoch(&epoch1, size1)

	epoch2 := epoch1.Next(size2, commitSecret2, context2)
	checkEpoch(&epoch2, size2)

	// Check that marshal/unmarshal works
	epoch2m, err := syntax.Marshal(epoch2)
	assertNotError(t, err, "Error in key schedule marshal")

	var epoch2u keyScheduleEpoch
	_, err = syntax.Unmarshal(epoch2m, &epoch2u)
	assertNotError(t, err, "Error in key schedule unmarshal")

	epoch2u.enableKeySources()

	// Verify that the contents match (not the group key generators)
	assertDeepEquals(t, epoch2.Suite, epoch2u.Suite)
	assertDeepEquals(t, epoch2.EpochSecret, epoch2u.EpochSecret)
	assertDeepEquals(t, epoch2.SenderDataSecret, epoch2u.SenderDataSecret)
	assertDeepEquals(t, epoch2.SenderDataKey, epoch2u.SenderDataKey)
	assertDeepEquals(t, epoch2.HandshakeSecret, epoch2u.HandshakeSecret)
	assertDeepEquals(t, epoch2.ApplicationSecret, epoch2u.ApplicationSecret)
	assertDeepEquals(t, epoch2.ConfirmationKey, epoch2u.ConfirmationKey)
	assertDeepEquals(t, epoch2.InitSecret, epoch2u.InitSecret)
	assertDeepEquals(t, epoch2.HandshakeBaseKeys, epoch2u.HandshakeBaseKeys)
	assertDeepEquals(t, epoch2.ApplicationBaseKeys, epoch2u.ApplicationBaseKeys)
	assertDeepEquals(t, epoch2.HandshakeRatchets, epoch2u.HandshakeRatchets)
	assertDeepEquals(t, epoch2.ApplicationRatchets, epoch2u.ApplicationRatchets)

	// Verify that we can't get a key for the target generation (because it's
	// already consumed)
	_, err = epoch2u.HandshakeKeys.Get(0, targetGeneration)
	assertError(t, err, "Replayed an already-used key")

	// Verify that we can get one for the next epoch, and it's the same as the
	// original key schedule would have produced
	_, err = epoch2u.HandshakeKeys.Get(0, targetGeneration+1)
	assertNotError(t, err, "Failed to get the next key")
}

///
/// Vectors
///

type KsEpoch struct {
	NumMembers       leafCount
	UpdateSecret     []byte        `tls:"head=1"`
	EpochSecret      []byte        `tls:"head=1"`
	SenderDataSecret []byte        `tls:"head=1"`
	SenderDataKey    []byte        `tls:"head=1"`
	HandshakeSecret  []byte        `tls:"head=1"`
	HandshakeKeys    []keyAndNonce `tls:"head=4"`
	AppSecret        []byte        `tls:"head=1"`
	AppKeys          []keyAndNonce `tls:"head=4"`
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
	BaseInitSecret   []byte       `tls:"head=1"`
	BaseGroupContext []byte       `tls:"head=4"`
	Cases            []KsTestCase `tls:"head=4"`
}

/// Gen and Verify
func generateKeyScheduleVectors(t *testing.T) []byte {
	var tv KsTestVectors
	suites := []CipherSuite{P256_SHA256_AES128GCM}
	baseGrpCtx := GroupContext{
		GroupID:                 []byte{0xA0, 0xA0, 0xA0, 0xA0},
		Epoch:                   0,
		TreeHash:                bytes.Repeat([]byte{0xA1}, 32),
		ConfirmedTranscriptHash: bytes.Repeat([]byte{0xA2}, 32),
	}

	encCtx, err := syntax.Marshal(baseGrpCtx)
	assertNotError(t, err, "grp context marshal")
	tv.NumEpochs = 50
	tv.TargetGeneration = 3
	tv.BaseGroupContext = encCtx
	tv.BaseInitSecret = bytes.Repeat([]byte{0xA3}, 32)

	for _, suite := range suites {
		var tc KsTestCase
		tc.CipherSuite = suite
		// start with the base context for epoch0
		grpCtx := baseGrpCtx
		updateSecret := bytes.Repeat([]byte{0x0}, suite.constants().SecretSize)
		minMembers := 5
		maxMembers := 20
		nMembers := minMembers

		var epoch keyScheduleEpoch
		epoch.Suite = suite
		epoch.InitSecret = tv.BaseInitSecret
		for i := 0; i < int(tv.NumEpochs); i++ {
			ctx, _ := syntax.Marshal(grpCtx)
			epoch = epoch.Next(leafCount(nMembers), updateSecret, ctx)
			var handshakeKeys []keyAndNonce
			var applicationKeys []keyAndNonce
			appSecret := dup(epoch.ApplicationSecret)
			for j := 0; j < nMembers; j++ {
				hs, _ := epoch.HandshakeKeys.Get(leafIndex(j), tv.TargetGeneration)
				handshakeKeys = append(handshakeKeys, hs)
				as, _ := epoch.ApplicationKeys.Get(leafIndex(j), tv.TargetGeneration)
				applicationKeys = append(applicationKeys, as)
			}
			kse := KsEpoch{
				NumMembers:       leafCount(nMembers),
				UpdateSecret:     dup(updateSecret),
				EpochSecret:      epoch.EpochSecret,
				SenderDataSecret: epoch.SenderDataSecret,
				SenderDataKey:    epoch.SenderDataKey,
				HandshakeSecret:  epoch.HandshakeSecret,
				HandshakeKeys:    handshakeKeys,
				AppSecret:        appSecret,
				AppKeys:          applicationKeys,
				ConfirmationKey:  epoch.ConfirmationKey,
				InitSecret:       epoch.InitSecret,
			}

			tc.Epochs = append(tc.Epochs, kse)
			for idx, val := range updateSecret {
				updateSecret[idx] = byte(val + 1)
			}

			grpCtx.Epoch += 1
			nMembers = (nMembers-minMembers)%(maxMembers-minMembers) + minMembers
		}
		tv.Cases = append(tv.Cases, tc)
	}

	vec, err := syntax.Marshal(tv)
	assertNotError(t, err, "Error marshaling test vectors")
	return vec
}

func verifyKeyScheduleVectors(t *testing.T, data []byte) {
	var tv KsTestVectors
	_, err := syntax.Unmarshal(data, &tv)
	assertNotError(t, err, "Malformed message test vectors")
	for _, tc := range tv.Cases {
		suite := tc.CipherSuite
		var grpCtx GroupContext
		_, err := syntax.Unmarshal(tv.BaseGroupContext, &grpCtx)
		assertNotError(t, err, "grpCtx unmarshal")
		var myEpoch keyScheduleEpoch
		myEpoch.Suite = suite
		myEpoch.InitSecret = tv.BaseInitSecret
		for _, epoch := range tc.Epochs {
			ctx, _ := syntax.Marshal(grpCtx)
			myEpoch = myEpoch.Next(epoch.NumMembers, epoch.UpdateSecret, ctx)
			// check the secrets
			assertByteEquals(t, myEpoch.EpochSecret, epoch.EpochSecret)
			assertByteEquals(t, myEpoch.SenderDataSecret, epoch.SenderDataSecret)
			assertByteEquals(t, myEpoch.SenderDataKey, epoch.SenderDataKey)
			assertByteEquals(t, myEpoch.HandshakeSecret, epoch.HandshakeSecret)
			assertByteEquals(t, myEpoch.ApplicationSecret, epoch.AppSecret)
			assertByteEquals(t, myEpoch.ConfirmationKey, epoch.ConfirmationKey)
			assertByteEquals(t, myEpoch.InitSecret, epoch.InitSecret)

			//check the keys
			for i := 0; leafCount(i) < epoch.NumMembers; i++ {
				hs, err := myEpoch.HandshakeKeys.Get(leafIndex(i), tv.TargetGeneration)
				assertNotError(t, err, "hs keys")
				assertByteEquals(t, hs.Key, epoch.HandshakeKeys[i].Key)
				assertByteEquals(t, hs.Nonce, epoch.HandshakeKeys[i].Nonce)

				as, err := myEpoch.ApplicationKeys.Get(leafIndex(i), tv.TargetGeneration)
				assertNotError(t, err, "as keys")
				assertByteEquals(t, as.Key, epoch.AppKeys[i].Key)
				assertByteEquals(t, as.Nonce, epoch.AppKeys[i].Nonce)

			}
			grpCtx.Epoch += 1
		}
	}
}
