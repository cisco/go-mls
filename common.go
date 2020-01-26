package mls

import (
	"fmt"
)

func validateEnum(v interface{}, known ...interface{}) error {
	for _, kv := range known {
		if v == kv {
			return nil
		}
	}
	return fmt.Errorf("Unknown enum value: %v", v)
}
