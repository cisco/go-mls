package mls

import (
	"fmt"

	"github.com/bifurcation/mint/syntax"
)

type ExtensionType uint16

const (
	ExtensionTypeParentHash ExtensionType = 0x0005
)

type ExtensionBody interface {
	Type() ExtensionType
}

type Extension struct {
	ExtensionType ExtensionType
	ExtensionData []byte `tls:"head=2"`
}

type ExtensionList struct {
	Entries []Extension `tls:"head=2"`
}

func (el *ExtensionList) Add(src ExtensionBody) error {
	data, err := syntax.Marshal(src)
	if err != nil {
		return err
	}

	// If one already exists with this type, replace it
	for i := range el.Entries {
		if el.Entries[i].ExtensionType == src.Type() {
			el.Entries[i].ExtensionData = data
			return nil
		}
	}

	// Otherwise append
	el.Entries = append(el.Entries, Extension{
		ExtensionType: src.Type(),
		ExtensionData: data,
	})
	return nil
}

func (el ExtensionList) Find(dst ExtensionBody) (bool, error) {
	for _, ext := range el.Entries {
		if ext.ExtensionType == dst.Type() {
			read, err := syntax.Unmarshal(ext.ExtensionData, dst)
			if err != nil {
				return true, err
			}

			if read != len(ext.ExtensionData) {
				return true, fmt.Errorf("Extension failed to consume all data")
			}

			return true, nil
		}
	}
	return false, nil
}

//////////

type ParentHashExtension struct {
	ParentHash []byte `tls:"head=1"`
}

func (phe ParentHashExtension) Type() ExtensionType {
	return ExtensionTypeParentHash
}
