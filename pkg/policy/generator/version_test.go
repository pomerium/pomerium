package generator

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetVersionFromRego(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		v := GetVersionFromRego(`package pomerium.policy #version=123`)
		assert.Equal(t, 123, v)
	})
	t.Run("missing", func(t *testing.T) {
		v := GetVersionFromRego(`package pomerium.policy`)
		assert.Equal(t, Version, v)
	})
	t.Run("non-number", func(t *testing.T) {
		v := GetVersionFromRego(`package pomerium.policy #version=XYZ`)
		assert.Equal(t, Version, v)
	})
}
