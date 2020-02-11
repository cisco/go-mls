package mls

import (
	"fmt"
)

func dup(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func validateEnum(v interface{}, known ...interface{}) error {
	for _, kv := range known {
		if v == kv {
			return nil
		}
	}
	return fmt.Errorf("Unknown enum value: %v", v)
}
