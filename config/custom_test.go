package config

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

func TestJWTClaimHeaders_UnmarshalJSON(t *testing.T) {
	t.Run("object", func(t *testing.T) {
		var hdrs JWTClaimHeaders
		err := json.Unmarshal([]byte(`{"x":"y"}`), &hdrs)
		assert.NoError(t, err)
		assert.Equal(t, JWTClaimHeaders{"x": "y"}, hdrs)
	})
	t.Run("array", func(t *testing.T) {
		var hdrs JWTClaimHeaders
		err := json.Unmarshal([]byte(`["x", "y"]`), &hdrs)
		assert.NoError(t, err)
		assert.Equal(t, JWTClaimHeaders{"x-pomerium-claim-x": "x", "x-pomerium-claim-y": "y"}, hdrs)
	})
	t.Run("string", func(t *testing.T) {
		var hdrs JWTClaimHeaders
		err := json.Unmarshal([]byte(`"x, y"`), &hdrs)
		assert.NoError(t, err)
		assert.Equal(t, JWTClaimHeaders{"x-pomerium-claim-x": "x", "x-pomerium-claim-y": "y"}, hdrs)
	})
}

func TestJWTClaimHeaders_UnmarshalYAML(t *testing.T) {
	t.Run("object", func(t *testing.T) {
		var hdrs JWTClaimHeaders
		err := yaml.Unmarshal([]byte(`
x: "y"
`), &hdrs)
		assert.NoError(t, err)
		assert.Equal(t, JWTClaimHeaders{"x": "y"}, hdrs)
	})
	t.Run("array", func(t *testing.T) {
		var hdrs JWTClaimHeaders
		err := yaml.Unmarshal([]byte(`
- x
- "y"
`), &hdrs)
		assert.NoError(t, err)
		assert.Equal(t, JWTClaimHeaders{"x-pomerium-claim-x": "x", "x-pomerium-claim-y": "y"}, hdrs)
	})
	t.Run("string", func(t *testing.T) {
		var hdrs JWTClaimHeaders
		err := yaml.Unmarshal([]byte(`"x, y"`), &hdrs)
		assert.NoError(t, err)
		assert.Equal(t, JWTClaimHeaders{"x-pomerium-claim-x": "x", "x-pomerium-claim-y": "y"}, hdrs)
	})
}

func TestDecodeJWTClaimHeadersHookFunc(t *testing.T) {
	var withClaims struct {
		Claims JWTClaimHeaders `mapstructure:"claims"`
	}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: decodeJWTClaimHeadersHookFunc(),
		Result:     &withClaims,
	})
	require.NoError(t, err)

	t.Run("object", func(t *testing.T) {
		err := decoder.Decode(struct {
			Claims map[string]string `mapstructure:"claims"`
		}{
			Claims: map[string]string{"a": "b", "c": "d"},
		})
		assert.NoError(t, err)
		assert.Equal(t, JWTClaimHeaders{
			"a": "b",
			"c": "d",
		}, withClaims.Claims)
	})

	withClaims.Claims = nil

	t.Run("array", func(t *testing.T) {
		err := decoder.Decode(struct {
			Claims []string `mapstructure:"claims"`
		}{
			Claims: []string{"a", "b", "c"},
		})
		assert.NoError(t, err)
		assert.Equal(t, JWTClaimHeaders{
			"x-pomerium-claim-a": "a",
			"x-pomerium-claim-b": "b",
			"x-pomerium-claim-c": "c",
		}, withClaims.Claims)
	})
}

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

	err = yaml.Unmarshal(data, &mi)
	require.NoError(t, err, "unmarshal")

	ms, err := serializable(mi)
	require.NoError(t, err, "serializable")

	_, err = json.Marshal(ms)
	require.NoError(t, err, "json marshal")
}

func TestWeightedStringSlice(t *testing.T) {
	tcases := []struct {
		In      StringSlice
		Out     StringSlice
		Weights []uint32
		Error   bool
	}{
		{
			StringSlice{"https://srv-1.int.corp.com,1", "https://srv-2.int.corp.com,2", "http://10.0.1.1:8080,3", "http://localhost:8000,4"},
			StringSlice{"https://srv-1.int.corp.com", "https://srv-2.int.corp.com", "http://10.0.1.1:8080", "http://localhost:8000"},
			[]uint32{1, 2, 3, 4},
			false,
		},
		{ // all should be provided
			StringSlice{"https://srv-1.int.corp.com,1", "https://srv-2.int.corp.com", "http://10.0.1.1:8080,3", "http://localhost:8000,4"},
			nil,
			nil,
			true,
		},
		{ // or none
			StringSlice{"https://srv-1.int.corp.com", "https://srv-2.int.corp.com", "http://10.0.1.1:8080", "http://localhost:8000"},
			StringSlice{"https://srv-1.int.corp.com", "https://srv-2.int.corp.com", "http://10.0.1.1:8080", "http://localhost:8000"},
			nil,
			false,
		},
		{ // IPv6 https://tools.ietf.org/html/rfc2732
			StringSlice{"http://[::FFFF:129.144.52.38]:8080,1", "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:8080/,2"},
			StringSlice{"http://[::FFFF:129.144.52.38]:8080", "http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:8080/"},
			[]uint32{1, 2},
			false,
		},
	}

	for _, tc := range tcases {
		name := fmt.Sprintf("%s", tc.In)
		out, weights, err := weightedStrings(tc.In)
		if tc.Error {
			assert.Error(t, err, name)
		} else {
			assert.NoError(t, err, name)
		}
		assert.Equal(t, tc.Out, out, name)
		assert.Equal(t, tc.Weights, weights, name)
	}
}
