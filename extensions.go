package mls

import (
	"fmt"

	syntax "github.com/cisco/go-tls-syntax"
)

type ExtensionType uint16

const (
	ExtensionTypeInvalid               ExtensionType = 0x0000
	ExtensionTypeSupportedVersions     ExtensionType = 0x0001
	ExtensionTypeSupportedCipherSuites ExtensionType = 0x0002
	ExtensionTypeLifetime              ExtensionType = 0x0003
	ExtensionTypeKeyID                 ExtensionType = 0x0004
	ExtensionTypeParentHash            ExtensionType = 0x0005
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

func NewExtensionList() ExtensionList {
	return ExtensionList{[]Extension{}}
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

func (el ExtensionList) Has(extType ExtensionType) bool {
	for _, ext := range el.Entries {
		if ext.ExtensionType == extType {
			return true
		}
	}
	return false
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

type SupportedVersionsExtension struct {
	SupportedVersions []ProtocolVersion `tls:"head=1"`
}

func (sve SupportedVersionsExtension) Type() ExtensionType {
	return ExtensionTypeSupportedVersions
}

//////////

type SupportedCipherSuitesExtension struct {
	SupportedCipherSuites []CipherSuite `tls:"head=1"`
}

func (sce SupportedCipherSuitesExtension) Type() ExtensionType {
	return ExtensionTypeSupportedCipherSuites
}

//////////

type LifetimeExtension struct {
	NotBefore uint64
	NotAfter  uint64
}

func (lte LifetimeExtension) Type() ExtensionType {
	return ExtensionTypeLifetime
}

//////////

type ParentHashExtension struct {
	ParentHash []byte `tls:"head=1"`
}

func (phe ParentHashExtension) Type() ExtensionType {
	return ExtensionTypeParentHash
}
