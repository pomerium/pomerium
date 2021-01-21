package config

import (
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
	data := []byte(`
health_check:
  timeout: 5s
  interval: 60s
  healthyThreshold: 1
  unhealthyThreshold: 2
  http_health_check: 
    host: "http://51.15.222.790:8080"
    path: "/"
`)
	var mi map[interface{}]interface{}

	err := yaml.Unmarshal(data, &mi)
	require.NoError(t, err, "unmarshal")

	ms, err := serializable(mi)
	require.NoError(t, err, "serializable")

	_, err = json.Marshal(ms)
	require.NoError(t, err, "json marshal")
}
