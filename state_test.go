package mls

import (
	"reflect"
	"testing"
)

var (
	aTestGroupSize = 5
)

func TestUserAdd(t *testing.T) {
	groupID := []byte("treehouse")
	creatorKey := NewECPrivateKey()
	creator, err := NewStateForEmptyGroup(groupID, creatorKey)
	if err != nil {
		t.Fatalf("Error in creating group: %v", err)
	}

	states := []*State{creator}

	for k := 1; k < aTestGroupSize; k += 1 {
		identityKey := NewECPrivateKey()
		leafKey := NewECPrivateKey()
		oldGPK, err := states[k-1].SignedGroupPreKey()
		if err != nil {
			t.Fatalf("Error in fetching GPK: %v", err)
		}

		add, err := Join(identityKey, leafKey, oldGPK)
		if err != nil {
			t.Fatalf("Error in creating join messages: %v", err)
		}

		// Update existing participants
		for i, s := range states {
			err = s.HandleUserAdd(add)
			if err != nil {
				t.Logf("%+v", reflect.TypeOf(add.Body))
				t.Fatalf("Error updating existing participant @ %d -> %d: %v", k-1, i, err)
			}
		}

		// Initialize the new participant
		newState, err := NewStateFromGroupPreKey(identityKey, leafKey, oldGPK)
		if err != nil {
			t.Fatalf("Error initializing new participant: %v", err)
		}

		states = append(states, newState)

		// Verify that everyone ended up in the right state
		if states[0].epoch != uint32(k) {
			t.Fatalf("Incorrect epoch @ %d: %v != %v", k, states[0].epoch, k)
		}

		for i := 1; i < len(states); i += 1 {
			if !states[i].Equal(states[0]) {
				t.Fatalf("State mismatch @ %d: %v != %v", k, i, 0)
			}
		}
	}
}

func TestGroupAdd(t *testing.T) {
	groupID := []byte("treehouse")
	creatorKey := NewECPrivateKey()
	creator, err := NewStateForEmptyGroup(groupID, creatorKey)
	if err != nil {
		t.Fatalf("Error in creating group: %v", err)
	}

	states := []*State{creator}

	for k := 1; k < aTestGroupSize; k += 1 {
		identityKey := NewECPrivateKey()
		preKey, upk, err := NewUserPreKey(identityKey)

		gpk, err := states[k-1].SignedGroupPreKey()
		if err != nil {
			t.Fatalf("Error in creating GroupPreKey: %v", err)
		}

		add, err := states[k-1].Add(upk)
		if err != nil {
			t.Fatalf("Error in creating GroupAdd: %v", err)
		}

		// Update existing participants
		for i, s := range states {
			err = s.HandleGroupAdd(add)
			if err != nil {
				t.Logf("%+v", reflect.TypeOf(add.Body))
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
		if states[0].epoch != uint32(k) {
			t.Fatalf("Incorrect epoch @ %d: %v != %v", k, states[0].epoch, k)
		}

		for i := 1; i < len(states); i += 1 {
			if !states[i].Equal(states[0]) {
				t.Fatalf("State mismatch @ %d: %v != %v", k, i, 0)
			}
		}
	}
}

// Create a group
// XXX Ignoring errors throughout; should be caught in TestUserAdd
func createGroup() []*State {
	groupID := []byte("treehouse")
	creatorKey := NewECPrivateKey()
	creator, _ := NewStateForEmptyGroup(groupID, creatorKey)
	states := []*State{creator}

	for k := 1; k < aTestGroupSize; k += 1 {
		identityKey := NewECPrivateKey()
		leafKey := NewECPrivateKey()
		oldGPK, _ := states[k-1].SignedGroupPreKey()
		add, _ := Join(identityKey, leafKey, oldGPK)

		for _, s := range states {
			s.HandleUserAdd(add)
		}

		newState, _ := NewStateFromGroupPreKey(identityKey, leafKey, oldGPK)
		states = append(states, newState)
	}

	return states
}

func TestUpdate(t *testing.T) {
	states := createGroup()

	// Update each participant
	for i, s0 := range states {
		leafKey := NewECPrivateKey()
		update, err := s0.Update(leafKey)
		if err != nil {
			t.Fatalf("Error generating update: %v", err)
		}

		err = s0.HandleSelfUpdate(leafKey, update)
		if err != nil {
			t.Fatalf("Error handling self-update: %v", err)
		}

		for j, s1 := range states {
			if i == j {
				continue
			}

			err = s1.HandleUpdate(update)
			if err != nil {
				t.Fatalf("Error updating %d -> %d: %v", i, j, err)
			}

			if !s0.Equal(s1) {
				t.Fatalf("State mismatch %d -> %d", i, j)
			}
		}
	}
}

func TestDelete(t *testing.T) {
	states := createGroup()

	// Import leaves and identities to the penultimate node
	identities := make([]MerkleNode, len(states))
	leafKeys := make([]ECPublicKey, len(states))
	for i, s := range states {
		leafKeys[i] = s.myLeafKey.PublicKey
		identities[i] = MerkleNodeFromPublicKey(s.myIdentityKey.PublicKey)
	}

	err := states[len(states)-2].importIdentities(identities)
	if err != nil {
		t.Fatalf("Error importing identities: %v", err)
	}

	err = states[len(states)-2].importLeaves(leafKeys)
	if err != nil {
		t.Fatalf("Error importing leaves: %v", err)
	}

	// Each node deletes its successor
	startingEpoch := states[0].epoch
	epochSteps := uint32(0)

	for k := uint(len(states) - 2); ; k -= 1 {
		delete, err := states[k].Delete([]uint{k + 1})
		if err != nil {
			t.Fatalf("Error generating delete @ %d: %v", k, err)
		}

		for i := uint(0); i <= k; i += 1 {
			err = states[i].HandleDelete(delete)
			if err != nil {
				t.Fatalf("Error handling delete @ %d -> %d: %v", k, i, err)
			}
		}

		// Check that the remaining nodes end up in the same place
		epochSteps += 1
		if states[k].epoch != startingEpoch+epochSteps {
			t.Fatalf("Incorrect epoch @ %d: %v != %v", k, states[k].epoch, startingEpoch+epochSteps)
		}

		for i := uint(k); i < k; i += 1 {
			if !states[i].Equal(states[k]) {
				t.Fatalf("State mismatch @ %d: %v != %v", k, i, 0)
			}
		}

		if k == 0 {
			break
		}
	}
}

func TestDeleteMultiple(t *testing.T) {
	states := createGroup()

	// Room creator deletes everyone but himself and the last participant
	startingEpoch := states[0].epoch

	toDelete := make([]uint, len(states))
	for i := range states {
		if i == 0 || i == len(states)-1 {
			continue
		}
		toDelete[i] = uint(i)
	}
	delete, err := states[0].Delete(toDelete)
	if err != nil {
		t.Fatalf("Error generating delete: %v", err)
	}

	err = states[0].HandleDelete(delete)
	if err != nil {
		t.Fatalf("Error handling delete (0): %v", err)
	}

	err = states[1].HandleDelete(delete)
	if err != nil {
		t.Fatalf("Error handling delete (1): %v", err)
	}

	if states[0].epoch != startingEpoch+1 {
		t.Fatalf("Incorrect epoch: %v", states[0].epoch, startingEpoch+1)
	}

	if !states[0].Equal(states[1]) {
		t.Fatalf("State mismatch")
	}
}

func TestChaosMonkey(t *testing.T) {
	// TODO For N steps, randomly decide to take one of the following actions:
	// * Add by a random member of the group
	// * Add by the new participant
	// * Update a random group member
	// * Delete a random set of group members by a random group member
}
