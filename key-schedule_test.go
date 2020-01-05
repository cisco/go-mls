package mls

import (
	"bytes"
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

	initSecret := unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	size1 := leafCount(5)
	commitSecret1 := unhex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	context1 := []byte("first")

	size2 := leafCount(11)
	commitSecret2 := unhex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")
	context2 := []byte("second")

	targetGeneration := uint32(3)

	epoch0 := newFirstEpoch(suite, initSecret)
	ok0 := (epoch0.Suite == suite) &&
		bytes.Equal(epoch0.InitSecret, initSecret) &&
		(len(epoch0.GroupInfoSecret) == secretSize) &&
		(len(epoch0.GroupInfoKey) == keySize) &&
		(len(epoch0.GroupInfoNonce) == nonceSize)
	if !ok0 {
		t.Fatalf("Malformed first epoch")
	}

	checkEpoch := func(epoch keyScheduleEpoch, size leafCount) {
		ok := (epoch.Suite == suite) &&
			(len(epoch.EpochSecret) == secretSize) &&
			(len(epoch.SenderDataSecret) == secretSize) &&
			(len(epoch.SenderDataKey) == keySize) &&
			(len(epoch.HandshakeSecret) == secretSize) &&
			(epoch.HandshakeKeys != nil) &&
			(len(epoch.ApplicationSecret) == secretSize) &&
			(epoch.ApplicationKeys != nil) &&
			(len(epoch.ConfirmationKey) == secretSize) &&
			(len(epoch.InitSecret) == secretSize)
		if !ok {
			t.Fatalf("Malformed epoch ")
		}

		for i := leafIndex(0); i < leafIndex(size); i += 1 {
			hs, err := epoch.HandshakeKeys.Get(i, targetGeneration)
			if len(hs.Key) != keySize || len(hs.Nonce) != nonceSize {
				if err != nil {
					t.Fatalf("Error in handshake key generation: %v", err)
				}
				t.Fatalf("Malformed handshake key")
			}

			app, err := epoch.ApplicationKeys.Get(i, targetGeneration)
			if err != nil {
				t.Fatalf("Error in application key generation: %v", err)
			}
			if len(app.Key) != keySize || len(app.Nonce) != nonceSize {
				t.Fatalf("Malformed application key")
			}
		}
	}

	epoch1 := epoch0.Next(size1, commitSecret1, context1)
	checkEpoch(epoch1, size1)

	epoch2 := epoch1.Next(size2, commitSecret2, context2)
	checkEpoch(epoch2, size2)
}
