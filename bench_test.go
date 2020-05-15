package mls

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func twoStates(b *testing.B) (*State, *State) {
	scheme := suite.scheme()
	zero := []byte{0}

	// A
	sigPrivA, err := scheme.Generate()
	credA := NewBasicCredential(userID, scheme, &sigPrivA)
	kpA, err := NewKeyPackage(suite, credA)
	require.Nil(b, err)

	// B
	sigPrivB, err := scheme.Generate()
	credB := NewBasicCredential(userID, scheme, &sigPrivB)
	kpB, err := NewKeyPackage(suite, credB)
	require.Nil(b, err)

	// Tree(A, B)
	tree := NewRatchetTree(suite)
	err = tree.AddLeaf(0, *kpA)
	require.Nil(b, err)

	err = tree.AddLeaf(1, *kpB)
	require.Nil(b, err)

	// StateA, StateB
	stateA := &State{
		Index:        0,
		CipherSuite:  suite,
		Scheme:       suite.scheme(),
		Tree:         *tree,
		IdentityPriv: sigPrivA,
		Keys:         newKeyScheduleEpoch(suite, 2, zero, zero),
	}
	stateB := &State{
		Index:        1,
		CipherSuite:  suite,
		Scheme:       suite.scheme(),
		Tree:         *tree,
		IdentityPriv: sigPrivB,
		Keys:         newKeyScheduleEpoch(suite, 2, zero, zero),
	}

	return stateA, stateB
}

func BenchmarkProtect(b *testing.B) {
	pt := make([]byte, 100)

	b.Run("protect/base", func(b *testing.B) {
		stateA, _ := twoStates(b)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			rand.Read(pt)
			stateA.ProtectBase(pt)
		}
	})

	b.Run("protect/full", func(b *testing.B) {
		stateA, _ := twoStates(b)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			rand.Read(pt)
			_, err := stateA.Protect(pt)
			require.Nil(b, err)
		}
	})

	b.Run("protect/anon", func(b *testing.B) {
		stateA, _ := twoStates(b)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			rand.Read(pt)
			_, err := stateA.ProtectAnonymous(pt)
			require.Nil(b, err)
		}
	})

	b.Run("protect/slim", func(b *testing.B) {
		stateA, _ := twoStates(b)
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			rand.Read(pt)
			_, err := stateA.ProtectSlim(pt)
			require.Nil(b, err)
		}
	})

	b.Run("unprotect/base", func(b *testing.B) {
		var err error
		stateA, stateB := twoStates(b)
		cts := make([][]byte, b.N)
		for i := range cts {
			rand.Read(pt)
			cts[i] = stateA.ProtectBase(pt)
		}

		b.ResetTimer()

		for _, ct := range cts {
			_, err = stateB.UnprotectBase(ct)
			require.Nil(b, err)
		}
	})

	b.Run("unprotect/full", func(b *testing.B) {
		var err error
		stateA, stateB := twoStates(b)
		cts := make([][]byte, b.N)
		for i := range cts {
			rand.Read(pt)
			cts[i], err = stateA.Protect(pt)
			require.Nil(b, err)
		}

		b.ResetTimer()

		for _, ct := range cts {
			_, err := stateB.Unprotect(ct)
			require.Nil(b, err)
		}
	})

	b.Run("unprotect/anon", func(b *testing.B) {
		var err error
		stateA, stateB := twoStates(b)
		cts := make([][]byte, b.N)
		for i := range cts {
			rand.Read(pt)
			cts[i], err = stateA.ProtectAnonymous(pt)
			require.Nil(b, err)
		}

		b.ResetTimer()

		for _, ct := range cts {
			_, err := stateB.UnprotectAnonymous(ct)
			require.Nil(b, err)
		}
	})

	b.Run("unprotect/slim", func(b *testing.B) {
		var err error
		stateA, stateB := twoStates(b)
		cts := make([][]byte, b.N)
		for i := range cts {
			rand.Read(pt)
			cts[i], err = stateA.ProtectSlim(pt)
			require.Nil(b, err)
		}

		b.ResetTimer()

		for _, ct := range cts {
			_, err := stateB.UnprotectSlim(ct)
			require.Nil(b, err)
		}
	})
}
