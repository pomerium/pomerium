package config

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hegel.dev/go/hegel"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestIdentityProvider_Validate(t *testing.T) {
	t.Parallel()

	valid := func() IdentityProvider {
		return IdentityProvider{
			Issuer:    "https://issuer.example.com",
			Audiences: []string{"pomerium"},
		}
	}

	t.Run("ok", func(t *testing.T) {
		assert.NoError(t, valid().Validate())
	})
	t.Run("ok with jwks_url", func(t *testing.T) {
		ip := valid()
		ip.JWKSURL = "https://issuer.example.com/keys"
		assert.NoError(t, ip.Validate())
	})
	t.Run("missing issuer", func(t *testing.T) {
		ip := valid()
		ip.Issuer = ""
		assert.Error(t, ip.Validate())
	})
	t.Run("bad jwks scheme", func(t *testing.T) {
		ip := valid()
		ip.JWKSURL = "ftp://bad"
		assert.Error(t, ip.Validate())
	})
	t.Run("issuer must be an absolute URL", func(t *testing.T) {
		ip := valid()
		ip.Issuer = "foo"
		assert.Error(t, ip.Validate())
	})
	t.Run("plaintext-http issuer rejected", func(t *testing.T) {
		// Fetching signing keys over http lets an on-path attacker substitute
		// the JWKS and forge acceptable tokens.
		ip := valid()
		ip.Issuer = "http://issuer.example.com"
		assert.Error(t, ip.Validate())
	})
	t.Run("plaintext-http jwks_url rejected", func(t *testing.T) {
		ip := valid()
		ip.JWKSURL = "http://issuer.example.com/keys"
		assert.Error(t, ip.Validate())
	})
	t.Run("loopback http allowed for local dev", func(t *testing.T) {
		ip := valid()
		ip.Issuer = "http://127.0.0.1:8080"
		ip.JWKSURL = "http://localhost:8080/keys"
		assert.NoError(t, ip.Validate())
	})
	t.Run("empty audiences fail-closed", func(t *testing.T) {
		ip := valid()
		ip.Audiences = nil
		assert.Error(t, ip.Validate())
		ip.Audiences = []string{}
		assert.Error(t, ip.Validate())
	})
	t.Run("supported_algs none rejected", func(t *testing.T) {
		ip := valid()
		ip.SupportedAlgs = []string{"none"}
		assert.Error(t, ip.Validate())
	})
	t.Run("supported_algs HS256 rejected", func(t *testing.T) {
		ip := valid()
		ip.SupportedAlgs = []string{"HS256"}
		assert.Error(t, ip.Validate())
	})
	t.Run("supported_algs unknown rejected", func(t *testing.T) {
		ip := valid()
		ip.SupportedAlgs = []string{"RS256", "bogus"}
		assert.Error(t, ip.Validate())
	})
	t.Run("supported_algs valid accepted", func(t *testing.T) {
		ip := valid()
		ip.SupportedAlgs = []string{"RS256", "ES384", "PS512", "EdDSA"}
		assert.NoError(t, ip.Validate())
	})
}

func TestIdentityProvider_EffectiveSupportedAlgs(t *testing.T) {
	t.Parallel()

	t.Run("default when unset", func(t *testing.T) {
		ip := IdentityProvider{Issuer: "https://x", Audiences: []string{"a"}}
		assert.Equal(t, []string{"RS256", "ES256", "EdDSA"}, ip.EffectiveSupportedAlgs())
	})
	t.Run("explicit passthrough", func(t *testing.T) {
		ip := IdentityProvider{SupportedAlgs: []string{"RS512"}}
		assert.Equal(t, []string{"RS512"}, ip.EffectiveSupportedAlgs())
	})
}

// TestApplySettings_IdentityProvidersMergeSemantics pins the setMap-style merge
// behavior: an empty incoming proto map is a no-op (Settings fragments are
// merged sequentially, so empty means "not set in this fragment"), while a
// non-empty map replaces the whole destination map.
func TestApplySettings_IdentityProvidersMergeSemantics(t *testing.T) {
	t.Parallel()

	base := map[string]IdentityProvider{
		"a": {Issuer: "https://a", Audiences: []string{"aud-a"}},
	}
	settingsWith := func(m map[string]*configpb.IdentityProvider) *configpb.Settings {
		s := NewDefaultOptions().ToProto().Settings
		s.IdentityProviders = m
		return s
	}

	t.Run("empty proto map is a no-op", func(t *testing.T) {
		o := NewDefaultOptions()
		o.IdentityProviders = maps.Clone(base)
		o.ApplySettings(context.Background(), nil, settingsWith(nil))
		require.Equal(t, base, o.IdentityProviders)
	})

	t.Run("non-empty proto map replaces whole map", func(t *testing.T) {
		o := NewDefaultOptions()
		o.IdentityProviders = maps.Clone(base)
		o.ApplySettings(context.Background(), nil, settingsWith(map[string]*configpb.IdentityProvider{
			"b": {Issuer: "https://b", Audiences: []string{"aud-b"}},
		}))
		require.Equal(t, map[string]IdentityProvider{
			"b": {Issuer: "https://b", Audiences: []string{"aud-b"}},
		}, o.IdentityProviders)
	})
}

// TestOptions_IdentityProvidersFromYAML pins viper's map-key lowercasing:
// provider names in the config become lowercase keys, so route references
// (Route.identity_providers) resolve deterministically regardless of the
// casing the operator typed.
func TestOptions_IdentityProvidersFromYAML(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	err := os.WriteFile(cfg, []byte(`
identity_providers:
  K8s-Prod:
    issuer: https://k8s.example.com
    audiences: [pomerium]
`), 0o644)
	require.NoError(t, err)

	o, err := newOptionsFromConfig(cfg)
	require.NoError(t, err)

	require.Contains(t, o.IdentityProviders, "k8s-prod")
	require.NotContains(t, o.IdentityProviders, "K8s-Prod")
	got := o.IdentityProviders["k8s-prod"]
	require.Equal(t, "https://k8s.example.com", got.Issuer)
	require.Equal(t, []string{"pomerium"}, got.Audiences)
}

func TestValidateIdentityProviders(t *testing.T) {
	t.Parallel()

	jwtFmt := configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT
	provider := IdentityProvider{Issuer: "https://issuer.example.com", Audiences: []string{"pomerium"}}
	jwtRoute := func() Policy {
		return Policy{RouteOptions: RouteOptions{BearerTokenFormat: nullable.From(jwtFmt)}}
	}

	t.Run("valid jwt route with provider", func(t *testing.T) {
		o := NewDefaultOptions()
		o.IdentityProviders = map[string]IdentityProvider{"k8s": provider}
		o.Policies = []Policy{jwtRoute()}
		assert.NoError(t, o.validateIdentityProviders())
	})

	t.Run("jwt route with zero providers", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Policies = []Policy{jwtRoute()}
		assert.Error(t, o.validateIdentityProviders())
	})

	t.Run("duplicate issuer across entries", func(t *testing.T) {
		o := NewDefaultOptions()
		o.IdentityProviders = map[string]IdentityProvider{
			"a": {Issuer: "https://dup", Audiences: []string{"x"}},
			"b": {Issuer: "https://dup", Audiences: []string{"y"}},
		}
		assert.Error(t, o.validateIdentityProviders())
	})

	t.Run("route references unknown provider", func(t *testing.T) {
		o := NewDefaultOptions()
		o.IdentityProviders = map[string]IdentityProvider{"k8s": provider}
		r := jwtRoute()
		r.IdentityProviders = []string{"nope"}
		o.Policies = []Policy{r}
		assert.Error(t, o.validateIdentityProviders())
	})

	t.Run("route references known provider ok", func(t *testing.T) {
		o := NewDefaultOptions()
		o.IdentityProviders = map[string]IdentityProvider{"k8s": provider}
		r := jwtRoute()
		r.IdentityProviders = []string{"k8s"}
		o.Policies = []Policy{r}
		assert.NoError(t, o.validateIdentityProviders())
	})

	t.Run("non-jwt route setting identity_providers errors", func(t *testing.T) {
		o := NewDefaultOptions()
		o.IdentityProviders = map[string]IdentityProvider{"k8s": provider}
		r := Policy{} // default (non-jwt) format
		r.IdentityProviders = []string{"k8s"}
		o.Policies = []Policy{r}
		assert.Error(t, o.validateIdentityProviders())
	})

	t.Run("global jwt format fallback respected", func(t *testing.T) {
		o := NewDefaultOptions()
		o.BearerTokenFormat = nullable.From(jwtFmt)
		o.IdentityProviders = map[string]IdentityProvider{"k8s": provider}
		o.Policies = []Policy{{}} // inherits global jwt format
		assert.NoError(t, o.validateIdentityProviders())
	})

	t.Run("global jwt format with zero providers errors", func(t *testing.T) {
		o := NewDefaultOptions()
		o.BearerTokenFormat = nullable.From(jwtFmt)
		o.Policies = []Policy{{}}
		assert.Error(t, o.validateIdentityProviders())
	})

	t.Run("invalid provider empty audiences", func(t *testing.T) {
		o := NewDefaultOptions()
		o.IdentityProviders = map[string]IdentityProvider{"k8s": {Issuer: "https://x"}}
		assert.Error(t, o.validateIdentityProviders())
	})

	t.Run("provider name with slash rejected", func(t *testing.T) {
		// '/' would break the injectivity of the "<provider>/<sub>" user id.
		o := NewDefaultOptions()
		o.IdentityProviders = map[string]IdentityProvider{"k8s/prod": provider}
		assert.Error(t, o.validateIdentityProviders())
	})

	t.Run("non-jwt route needs nothing", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Policies = []Policy{{}}
		assert.NoError(t, o.validateIdentityProviders())
	})
}

// TestPolicy_IdentityProvidersProtoRoundTrip checks that a route's provider-name
// allowlist survives the Policy <-> proto Route conversion. It is a plain
// repeated string; an empty/nil list means "all configured providers".
func TestPolicy_IdentityProvidersProtoRoundTrip(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		names := hegel.Draw(ht, hegel.Lists(hegel.Text().MaxSize(20)).MaxSize(5))

		httpsRedirect := true
		src := Policy{
			From:     "https://from.example.com",
			Redirect: &PolicyRedirect{HTTPSRedirect: &httpsRedirect},
		}
		src.IdentityProviders = names

		pb, err := src.ToProto()
		if err != nil {
			ht.Fatalf("ToProto: %v", err)
		}
		dst, err := NewPolicyFromProto(pb)
		if err != nil {
			ht.Fatalf("NewPolicyFromProto: %v", err)
		}
		// nil and empty are equivalent ("all providers"); slices.Equal treats them so.
		if !slices.Equal(dst.IdentityProviders, names) {
			ht.Fatalf("identity_providers mismatch: got %v want %v", dst.IdentityProviders, names)
		}
	})
}

// TestIdentityProviders_ProtoRoundTrip is the core property of the config-reload
// path: a map of identity providers must survive the Options-struct <-> proto
// conversion byte-for-byte. A field dropped or a key mangled here silently
// changes which providers/keys/algs/audiences Pomerium will trust.
func TestIdentityProviders_ProtoRoundTrip(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		n := hegel.Draw(ht, hegel.Integers(1, 5))
		src := make(map[string]IdentityProvider, n)
		for i := range n {
			// index prefix guarantees distinct keys
			name := fmt.Sprintf("idp-%d-%s", i, hegel.Draw(ht, hegel.Text().MaxSize(10)))
			src[name] = IdentityProvider{
				Issuer:        hegel.Draw(ht, hegel.Text().MaxSize(40)),
				JWKSURL:       hegel.Draw(ht, hegel.Text().MaxSize(40)),
				SupportedAlgs: hegel.Draw(ht, hegel.Lists(hegel.Text().MaxSize(10)).MaxSize(5)),
				Audiences:     hegel.Draw(ht, hegel.Lists(hegel.Text().MaxSize(10)).MaxSize(5)),
			}
		}

		var dst map[string]IdentityProvider
		setIdentityProviders(&dst, identityProvidersToProto(src))

		if len(dst) != len(src) {
			ht.Fatalf("length changed: got %d want %d", len(dst), len(src))
		}
		for name, want := range src {
			got, ok := dst[name]
			if !ok {
				ht.Fatalf("missing key %q", name)
			}
			if got.Issuer != want.Issuer {
				ht.Fatalf("issuer[%q] mismatch: got %q want %q", name, got.Issuer, want.Issuer)
			}
			if got.JWKSURL != want.JWKSURL {
				ht.Fatalf("jwks_url[%q] mismatch: got %q want %q", name, got.JWKSURL, want.JWKSURL)
			}
			// nil and empty are equivalent; slices.Equal treats them so.
			if !slices.Equal(got.SupportedAlgs, want.SupportedAlgs) {
				ht.Fatalf("supported_algs[%q] mismatch: got %v want %v", name, got.SupportedAlgs, want.SupportedAlgs)
			}
			if !slices.Equal(got.Audiences, want.Audiences) {
				ht.Fatalf("audiences[%q] mismatch: got %v want %v", name, got.Audiences, want.Audiences)
			}
		}
	})
}
