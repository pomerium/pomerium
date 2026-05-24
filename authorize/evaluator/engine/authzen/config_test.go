package authzen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeConfig(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		c, err := decodeConfig(nil)
		require.NoError(t, err)
		assert.Equal(t, "", c.Endpoint)
	})

	t.Run("pointer", func(t *testing.T) {
		t.Parallel()
		in := &Config{Endpoint: "https://pdp", AuthHeader: "Bearer x"}
		c, err := decodeConfig(in)
		require.NoError(t, err)
		assert.Equal(t, "https://pdp", c.Endpoint)
		assert.Equal(t, "Bearer x", c.AuthHeader)
		// Decoded value must be a copy: mutating it must not touch the
		// source.
		c.Endpoint = "mutated"
		assert.Equal(t, "https://pdp", in.Endpoint)
	})

	t.Run("map", func(t *testing.T) {
		t.Parallel()
		c, err := decodeConfig(map[string]any{
			"endpoint":     "https://pdp.example.com",
			"auth_header":  "Bearer abc",
			"subject_type": "person",
		})
		require.NoError(t, err)
		assert.Equal(t, "https://pdp.example.com", c.Endpoint)
		assert.Equal(t, "Bearer abc", c.AuthHeader)
		assert.Equal(t, "person", c.SubjectType)
	})

	t.Run("map with duration string", func(t *testing.T) {
		// YAML and mapstructure surface time.Duration values as strings
		// (e.g. "2s"); decodeConfig must accept that shape so operators
		// can write `timeout: 2s` under external_policy_engine.
		t.Parallel()
		c, err := decodeConfig(map[string]any{
			"endpoint": "https://pdp.example.com",
			"timeout":  "2s",
		})
		require.NoError(t, err)
		assert.Equal(t, 2*time.Second, c.Timeout)
	})

	t.Run("map with numeric duration", func(t *testing.T) {
		// time.Duration round-tripped through encoding/json arrives as a
		// number of nanoseconds; preserve that path for callers that
		// supply pre-decoded values.
		t.Parallel()
		c, err := decodeConfig(map[string]any{
			"endpoint": "https://pdp.example.com",
			"timeout":  int64(3 * time.Second),
		})
		require.NoError(t, err)
		assert.Equal(t, 3*time.Second, c.Timeout)
	})

	t.Run("unsupported", func(t *testing.T) {
		t.Parallel()
		_, err := decodeConfig(123)
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})
}
