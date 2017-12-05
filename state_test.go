package mls

import (
	"testing"
)

var (
	aTestGroupSize = 5
)

func TestUserAdd(t *testing.T) {
	// TODO
}

func TestGroupAdd(t *testing.T) {
	groupID := []byte("treehouse")
	creatorKey := NewECKey()
	creator, err := NewStateForEmptyGroup(groupID, creatorKey)
	if err != nil {
		t.Fatalf("Error in creating group: %v", err)
	}

	states := []*State{creator}

	for k := 1; k < aTestGroupSize; k += 1 {
		identityKey := NewECKey()
		preKey := NewECKey()

		upk := UserPreKey{PreKey: preKey}
		supk, err := NewSigned(upk, identityKey)
		if err != nil {
			t.Fatalf("Error in creating UserPreKey: %v", err)
		}

		gpk, err := states[k-1].groupPreKey()
		if err != nil {
			t.Fatalf("Error in creating GroupPreKey: %v", err)
		}

		add, err := states[k-1].Add(supk)
		if err != nil {
			t.Fatalf("Error in creating GroupAdd: %v", err)
		}

		// Update existing participants
		for i, s := range states {
			err = s.HandleGroupAdd(add)
			if err != nil {
				t.Fatalf("Error updating existing participant @ %d -> %d: %v", k-1, i, err)
			}
		}

		// Initialize the new participant
		newState, err := NewStateFromGroupAdd(identityKey, preKey, add, gpk)
		if err != nil {
			t.Fatalf("Error initializing new participant: %v", err)
		}

		states = append(states, newState)

		// Verify that everyone ended up in the right state
		if states[0].epoch != uint(k) {
			t.Fatalf("Incorrect epoch @ %d: %v != %v", k, states[0].epoch, k)
		}

		for i := 1; i < len(states); i += 1 {
			if !states[i].Equal(states[0]) {
				t.Fatalf("State mismatch @ %d: %v != %v", k, i, 0)
			}
		}
	}
}

func TestUpdate(t *testing.T) {
	// TODO
}

func TestDelete(t *testing.T) {
	// TODO
}

func TestDeleteMultiple(t *testing.T) {
	// TODO
}
