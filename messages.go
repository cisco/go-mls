package mls

import ()

type UserPreKey struct {
	LeafKey ECKey
}

type GroupPreKey struct {
	Epoch                uint
	GroupID              []byte
	UpdateKey            *ECKey
	IdentityTreeFrontier MerkleFrontier
	LeafTreeFrontier     MerkleFrontier
	RatchetTreeFrontier  ECFrontier
}

type UserAdd struct {
	AddPath []*ECKey
}

type GroupAdd struct {
	PreKey    Signed
	UpdateKey *ECKey
}

type Update struct {
	LeafPath    [][]byte
	RatchetPath []*ECKey
}

type Delete struct {
	Deleted    []uint
	Path       []*ECKey
	Leaves     []*ECKey
	Identities [][]byte
}

// TODO Signed
type Signed struct{}

// TODO RosterSigned
type RosterSigned struct{}
