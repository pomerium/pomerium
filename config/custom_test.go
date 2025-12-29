package config

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-viper/mapstructure/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"gopkg.in/yaml.v3"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
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

	var mi map[any]any

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

	err = decoder.Decode(map[string]any{
		"policy": map[string]any{
			"allow": map[string]any{
				"or": []map[string]any{
					{"email": map[string]any{
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

func TestDecodeProtoHookFunc(t *testing.T) {
	t.Parallel()

	var obj struct {
		OutlierDetection *configpb.OutlierDetection `mapstructure:"outlier_detection"`
	}
	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: decodeProtoHookFunc(),
		Result:     &obj,
	})
	require.NoError(t, err)

	err = decoder.Decode(map[string]any{
		"outlier_detection": map[string]any{
			"consecutive_5xx": 27,
		},
	})
	assert.NoError(t, err)
	assert.Empty(t, cmp.Diff(&configpb.OutlierDetection{
		Consecutive_5Xx: wrapperspb.UInt32(27),
	}, obj.OutlierDetection, protocmp.Transform()))
}
