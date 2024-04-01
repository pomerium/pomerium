package config

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/pomerium/pomerium/pkg/policy/parser"
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
	t.Parallel()

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

func TestDecodePPLPolicyHookFunc(t *testing.T) {
	var withPolicy struct {
		Policy *PPLPolicy `mapstructure:"policy"`
	}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: decodePPLPolicyHookFunc(),
		Result:     &withPolicy,
	})
	require.NoError(t, err)

	err = decoder.Decode(map[string]interface{}{
		"policy": map[string]interface{}{
			"allow": map[string]interface{}{
				"or": []map[string]interface{}{
					{"email": map[string]interface{}{
						"is": "user1@example.com",
					}},
				},
			},
		},
	})
	assert.NoError(t, err)
	assert.Equal(t, &PPLPolicy{
		Policy: &parser.Policy{
			Rules: []parser.Rule{{
				Action: parser.ActionAllow,
				Or: []parser.Criterion{{
					Name: "email", Data: parser.Object{
						"is": parser.String("user1@example.com"),
					},
				}},
			}},
		},
	}, withPolicy.Policy)
}

func TestDecodeRuntimeFlagsHookFunc(t *testing.T) {
	t.Parallel()

	t.Run("valid", func(t *testing.T) {
		t.Parallel()

		defaults := DefaultRuntimeFlags()
		withMap := struct {
			SomethingElse map[string]bool `mapstructure:"something_else"`
			RuntimeFlags  RuntimeFlags    `mapstructure:"runtime_flags"`
		}{
			RuntimeFlags: defaults,
		}

		decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			DecodeHook: decodeRuntimeFlagsHookFunc(),
			Result:     &withMap,
		})
		require.NoError(t, err)

		expect := DefaultRuntimeFlags()
		expect[GRPCDatabrokerKeepalive] = !expect[GRPCDatabrokerKeepalive]

		err = decoder.Decode(map[string]interface{}{
			"something_else": map[string]bool{
				"hello": true,
			},
			"runtime_flags": map[string]interface{}{
				string(GRPCDatabrokerKeepalive): expect[GRPCDatabrokerKeepalive],
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, expect, withMap.RuntimeFlags)
	})

	t.Run("dont override if unset", func(t *testing.T) {
		t.Parallel()

		defaults := DefaultRuntimeFlags()
		withMap := struct {
			RuntimeFlags RuntimeFlags `mapstructure:"runtime_flags"`
		}{
			RuntimeFlags: defaults,
		}

		decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			DecodeHook: decodeRuntimeFlagsHookFunc(),
			Result:     &withMap,
		})
		require.NoError(t, err)

		err = decoder.Decode(map[string]interface{}{})
		assert.NoError(t, err)
		assert.Equal(t, defaults, withMap.RuntimeFlags)
	})

	// mapstructure does not correctly wrap errors, so we will have to just search for the error text
	// https://github.com/mitchellh/mapstructure/blob/ab69d8d93410fce4361f4912bb1ff88110a81311/error.go#L35-L38
	assertErrorIs := func(t *testing.T, err error, target error) {
		t.Helper()
		if assert.Error(t, err) {
			strings.Contains(err.Error(), target.Error())
		}
	}

	t.Run("invalid input", func(t *testing.T) {
		t.Parallel()

		var withMap struct {
			RuntimeFlags RuntimeFlags `mapstructure:"runtime_flags"`
		}

		decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			DecodeHook: decodeRuntimeFlagsHookFunc(),
			Result:     &withMap,
		})
		require.NoError(t, err)

		err = decoder.Decode(map[string]interface{}{
			"runtime_flags": "hello world",
		})
		assertErrorIs(t, err, ErrRuntimeFlagsInvalidValue)

		err = decoder.Decode(map[string]interface{}{
			"runtime_flags": map[string]interface{}{
				"no_such_flag": true,
			},
		})
		assertErrorIs(t, err, ErrRuntimeFlagUnknown)

		err = decoder.Decode(map[string]interface{}{
			"runtime_flags": map[string]interface{}{
				string(GRPCDatabrokerKeepalive): "hello world",
			},
		})
		assertErrorIs(t, err, ErrRuntimeFlagInvalidMapValue)
	})
}
