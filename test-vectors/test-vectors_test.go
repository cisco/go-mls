package vectors

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func jsonRoundTrip(t *testing.T, original, decoded interface{}) {
	encoded, err := json.Marshal(original)
	require.NoError(t, err)

	err = json.Unmarshal(encoded, decoded)
	require.NoError(t, err)
}

func TestTreeMath(t *testing.T) {
	vec, err := NewTreeMath(10)
	require.NoError(t, err)

	var vec2 TreeMath
	jsonRoundTrip(t, vec, &vec2)
	require.NoError(t, vec2.Verify())
}
