package mls

///
/// TreeSecrets
///
type TreeSecrets struct {
	PrivateKeys map[nodeIndex]HPKEPrivateKey
}

func NewTreeSecrets() *TreeSecrets {
	return &TreeSecrets{
		PrivateKeys: map[nodeIndex]HPKEPrivateKey{},
	}
}

func (ts *TreeSecrets) Clone() *TreeSecrets {
	if ts == nil {
		return NewTreeSecrets()
	}

	out := NewTreeSecrets()
	for i, pk := range ts.PrivateKeys {
		out.PrivateKeys[i] = pk
	}
	return out
}

///
/// StateSecrets
///
type StateSecrets struct {
	Keys          keyScheduleEpoch
	IdentityPriv  SignaturePrivateKey
	Tree          TreeSecrets
	UpdateSecrets map[string][]byte
}

func (ss StateSecrets) Next() *StateSecrets {
	clone := &StateSecrets{
		// These are specific to an epoch, so not copied forward
		Keys: keyScheduleEpoch{},

		// These continue from one epoch to another
		IdentityPriv: ss.IdentityPriv,
		Tree:         *ss.Tree.Clone(),

		// XXX(RLB): These are copied, but just for purposes of initializing the new
		// state.  This can probably be avoided.
		UpdateSecrets: map[string][]byte{},
	}

	// Note that this is a shallow copy of slice pointers
	for key, value := range ss.UpdateSecrets {
		clone.UpdateSecrets[key] = value
	}

	return clone
}
