package mls

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

// TODO MarshalTLS / UnmarshalTLS
