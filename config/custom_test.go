package config

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestStringSlice_UnmarshalJSON(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		var slc StringSlice
		json.Unmarshal([]byte(`"hello world"`), &slc)
		assert.Equal(t, NewStringSlice("hello world"), slc)
	})
	t.Run("array", func(t *testing.T) {
		var slc StringSlice
		json.Unmarshal([]byte(`["a","b","c"]`), &slc)
		assert.Equal(t, NewStringSlice("a", "b", "c"), slc)
	})
}

func TestStringSlice_UnmarshalYAML(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		var slc StringSlice
		yaml.Unmarshal([]byte(`hello world`), &slc)
		assert.Equal(t, NewStringSlice("hello world"), slc)
	})
	t.Run("array", func(t *testing.T) {
		var slc StringSlice
		yaml.Unmarshal([]byte(`
- a
- b
- c
`), &slc)
		assert.Equal(t, NewStringSlice("a", "b", "c"), slc)
	})
}
func TestSerializable(t *testing.T) {
	data, err := base64.StdEncoding.DecodeString("aGVhbHRoX2NoZWNrOgogIHRpbWVvdXQ6IDVzCiAgaW50ZXJ2YWw6IDYwcwogIGhlYWx0aHlUaHJlc2hvbGQ6IDEKICB1bmhlYWx0aHlUaHJlc2hvbGQ6IDIKICBodHRwX2hlYWx0aF9jaGVjazogCiAgICBob3N0OiAiaHR0cDovL2xvY2FsaG9zdDo4MDgwIgogICAgcGF0aDogIi8iCg==")
	require.NoError(t, err, "decode")

	var mi map[interface{}]interface{}

	err = yaml.Unmarshal([]byte(data), &mi)
	require.NoError(t, err, "unmarshal")

	ms, err := serializable(mi)
	require.NoError(t, err, "serializable")

	_, err = json.Marshal(ms)
	require.NoError(t, err, "json marshal")
}
