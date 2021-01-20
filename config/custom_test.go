package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestStringSlice_UnmarshalJSON(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		var slc StringSlice
		json.Unmarshal([]byte(`"hello world"`), &slc)
		assert.Equal(t, StringSlice{"hello world"}, slc)
	})
	t.Run("array", func(t *testing.T) {
		var slc StringSlice
		json.Unmarshal([]byte(`["a","b","c"]`), &slc)
		assert.Equal(t, StringSlice{"a", "b", "c"}, slc)
	})
}

func TestStringSlice_UnmarshalYAML(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		var slc StringSlice
		yaml.Unmarshal([]byte(`hello world`), &slc)
		assert.Equal(t, StringSlice{"hello world"}, slc)
	})
	t.Run("array", func(t *testing.T) {
		var slc StringSlice
		yaml.Unmarshal([]byte(`
- a
- b
- c
`), &slc)
		assert.Equal(t, StringSlice{"a", "b", "c"}, slc)
	})
}
