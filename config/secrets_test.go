package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

func writeTempConfig(t *testing.T, yaml string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte(yaml), 0o600))
	return p
}

func TestSecretsOptionsDecode(t *testing.T) {
	cfg := writeTempConfig(t, `
secrets:
  defaults:
    refresh: 5m
    stale_grace: 30m
    negative_ttl: 30s
  bindings:
    upstream-api-token:
      url: "file:///etc/pomerium/secrets/token"
      refresh: 1m
`)
	o, err := newOptionsFromConfig(cfg)
	require.NoError(t, err)

	assert.Equal(t, 5*time.Minute, o.Secrets.Defaults.Refresh)
	assert.Equal(t, 30*time.Minute, o.Secrets.Defaults.StaleGrace)
	assert.Equal(t, 30*time.Second, o.Secrets.Defaults.NegativeTTL)

	b, ok := o.Secrets.Bindings["upstream-api-token"]
	require.True(t, ok)
	assert.Equal(t, "file:///etc/pomerium/secrets/token", b.URL)
	assert.Equal(t, time.Minute, b.Refresh)
}

func TestSecretsOptionsAbsent(t *testing.T) {
	o := NewDefaultOptions()
	assert.Empty(t, o.Secrets.Bindings)
	assert.NoError(t, o.validateSecrets(), "absence of a secrets block does not affect validation")
}

func TestSecretsOptionsProtoRoundTrip(t *testing.T) {
	orig := SecretsOptions{
		Defaults: SecretsDefaultsOptions{
			Refresh:     5 * time.Minute,
			StaleGrace:  30 * time.Minute,
			NegativeTTL: 30 * time.Second,
		},
		Bindings: map[string]SecretsBindingOptions{
			"full":     {URL: "file:///etc/a", Refresh: time.Minute, StaleGrace: 10 * time.Minute},
			"url-only": {URL: "file:///etc/b"},
		},
	}

	p := orig.ToProto()
	require.NotNil(t, p)

	var got SecretsOptions
	got.applySettingsProto(p)
	assert.Equal(t, orig, got)

	// Absence round-trips too.
	var empty SecretsOptions
	assert.Nil(t, empty.ToProto())
	var target SecretsOptions
	target.applySettingsProto(empty.ToProto())
	assert.Equal(t, SecretsOptions{}, target)
}

func TestApplySettingsSecrets(t *testing.T) {
	settings := &configpb.Settings{
		Secrets: &configpb.SecretsSettings{
			Bindings: map[string]*configpb.SecretsBinding{
				"tok": {Url: "file:///etc/token", Refresh: durationpb.New(time.Minute)},
			},
		},
	}

	o := NewDefaultOptions()
	o.ApplySettings(context.Background(), nil, settings)

	b, ok := o.Secrets.Bindings["tok"]
	require.True(t, ok)
	assert.Equal(t, "file:///etc/token", b.URL)
	assert.Equal(t, time.Minute, b.Refresh)
}

func TestSecretResidue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "malformed nesting", value: "${secret.${pomerium.email}}", want: true},
		{name: "malformed nesting mid-value", value: "x ${secret.${pomerium.email}} y", want: true},
		{name: "valid braced ref", value: "Bearer ${secret.tok}", want: false},
		{name: "valid simple ref", value: "$secret.tok", want: false},
		{name: "dollar escape is a literal, not a ref", value: "$$secret.name", want: false},
		{name: "escaped braced literal", value: "cost is $$secret", want: false},
		{name: "plain text", value: "no refs here", want: false},
		{name: "pomerium ref only", value: "u=${pomerium.user.id}", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, secretResidue(tt.value))
		})
	}
}

func TestValidateSecretsEscapedDollarNotRejected(t *testing.T) {
	t.Parallel()

	// "$$secret.name" is the escape for a literal "$secret.name"; it must not be
	// rejected as a malformed secret reference.
	o := NewDefaultOptions()
	o.Secrets = SecretsOptions{
		Bindings: map[string]SecretsBindingOptions{
			"tok": {URL: "file:///etc/pomerium/secrets/token"},
		},
	}
	o.Routes = []Policy{{
		From:              "https://app.example.com",
		SetRequestHeaders: map[string]string{"X-Literal": "$$secret.name"},
	}}
	assert.NoError(t, o.validateSecrets())
}

func TestValidateSecretsRouteReferences(t *testing.T) {
	withBinding := func() SecretsOptions {
		return SecretsOptions{
			Bindings: map[string]SecretsBindingOptions{
				"upstream-api-token": {URL: "file:///etc/pomerium/secrets/token"},
			},
		}
	}
	route := func(reqHeaders, respHeaders map[string]string) Policy {
		p := Policy{From: "https://app.example.com"}
		p.SetRequestHeaders = reqHeaders
		p.SetResponseHeaders = respHeaders
		return p
	}

	t.Run("matching binding is valid", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Secrets = withBinding()
		o.Routes = []Policy{route(map[string]string{
			"Authorization": "Bearer ${secret.upstream-api-token}",
			"X-Signed":      "user=${pomerium.user.id} sig=${secret.upstream-api-token}",
		}, nil)}
		assert.NoError(t, o.validateSecrets())
	})

	t.Run("unknown id errors with route, header, id", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Secrets = withBinding()
		o.Routes = []Policy{route(map[string]string{"Authorization": "Bearer ${secret.typo}"}, nil)}
		err := o.validateSecrets()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "typo")
		assert.Contains(t, err.Error(), "app.example.com")
		assert.Contains(t, err.Error(), "Authorization")
	})

	t.Run("too many segments", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Secrets = withBinding()
		o.Routes = []Policy{route(map[string]string{"X": "${secret.a.b}"}, nil)}
		err := o.validateSecrets()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exactly one ID segment")
	})

	t.Run("malformed nesting caught by residue rule", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Secrets = withBinding()
		o.Routes = []Policy{route(map[string]string{"X": "${secret.${pomerium.email}}"}, nil)}
		err := o.validateSecrets()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "malformed secret reference")
	})

	t.Run("secret ref in route response header rejected", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Secrets = withBinding()
		o.Routes = []Policy{route(nil, map[string]string{"X": "${secret.upstream-api-token}"})}
		err := o.validateSecrets()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "response headers")
	})

	t.Run("secret ref in global response header rejected", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Secrets = withBinding()
		o.SetResponseHeaders = map[string]string{"X": "${secret.upstream-api-token}"}
		err := o.validateSecrets()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "response headers")
	})

	t.Run("refs without a secrets block list the ids", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Routes = []Policy{route(map[string]string{
			"A": "${secret.foo}",
			"B": "${secret.bar}",
		}, nil)}
		err := o.validateSecrets()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "foo")
		assert.Contains(t, err.Error(), "bar")
	})

	t.Run("no block and no refs is a no-op", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Routes = []Policy{route(map[string]string{"A": "Bearer ${pomerium.access_token}"}, nil)}
		assert.NoError(t, o.validateSecrets())
	})

	t.Run("invalid binding url names the id", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Secrets = SecretsOptions{
			Bindings: map[string]SecretsBindingOptions{
				"bad": {URL: "file://host/path"},
			},
		}
		err := o.validateSecrets()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "bad")
	})
}
