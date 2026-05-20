package authzen

import (
	"testing"

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

	t.Run("value", func(t *testing.T) {
		t.Parallel()
		c, err := decodeConfig(Config{Endpoint: "https://pdp"})
		require.NoError(t, err)
		assert.Equal(t, "https://pdp", c.Endpoint)
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

	t.Run("unsupported", func(t *testing.T) {
		t.Parallel()
		_, err := decodeConfig(123)
		assert.ErrorIs(t, err, ErrInvalidConfig)
	})
}
