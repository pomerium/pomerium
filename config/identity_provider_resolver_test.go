package config

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hegel.dev/go/hegel"

	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	"github.com/pomerium/pomerium/pkg/derivecert"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/identity/oidc/extjwt"
)

func TestUnverifiedIssuer(t *testing.T) {
	t.Parallel()

	// No idp.Start: unverifiedIssuer only parses payload bytes, no network.
	idp := mockidp.New(mockidp.Config{})

	tok := idp.SignJWT(map[string]any{"iss": "https://example.com", "exp": time.Now().Add(time.Hour).Unix()})
	iss, err := unverifiedIssuer(tok)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com", iss)

	_, err = unverifiedIssuer("not-a-jwt")
	assert.Error(t, err)
}

// encodeUnsignedJWT builds a syntactically-valid (header.payload.sig) JWT with
// the given claims. The signature is a placeholder — unverifiedIssuer only
// parses the payload, it does not verify.
func encodeUnsignedJWT(t testing.TB, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadBytes, err := json.Marshal(claims)
	require.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(payloadBytes)
	return header + "." + payload + ".c2ln"
}

// TestUnverifiedIssuer_RoundTrip is the core property of the issuer-dispatch
// parser: for any non-empty iss claim, unverifiedIssuer must recover exactly
// the iss that was encoded. If the byte-for-byte iss the dispatcher reads ever
// diverges from what was in the token, the wrong provider (and thus the wrong
// signing keys / verifier) could be selected.
func TestUnverifiedIssuer_RoundTrip(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		iss := hegel.Draw(ht, hegel.Text().MinSize(1))
		ht.Assume(iss != "") // empty iss is a documented error, not a roundtrip case

		tok := encodeUnsignedJWT(ht.T, map[string]any{
			"iss": iss,
			"sub": "whatever",
		})
		got, err := unverifiedIssuer(tok)
		if err != nil {
			ht.Fatalf("unverifiedIssuer returned error for iss=%q: %v", iss, err)
		}
		if got != iss {
			ht.Fatalf("iss roundtrip mismatch: encoded %q, parsed %q", iss, got)
		}
	})
}

// TestUnverifiedIssuer_NoCrash is a robustness property: unverifiedIssuer
// processes the raw, attacker-controlled bearer token BEFORE any verification,
// so it must never panic on arbitrary input — it must only ever return a value
// or an error.
func TestUnverifiedIssuer_NoCrash(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		raw := hegel.Draw(ht, hegel.Text())
		_, _ = unverifiedIssuer(raw) // must not panic
	})
}

// Both of these are rejected by Options.Validate long before a resolver is built,
// so what matters here is that the defense in depth behind it costs the offending
// provider only. Sorted-name order decides which of a colliding pair that is.
func TestNewIdentityProviderResolver_DuplicateIssuer(t *testing.T) {
	t.Parallel()
	r := newIdentityProviderResolver(t.Context(), map[string]IdentityProvider{
		"a": {Issuer: "https://dup", Audiences: []string{"x"}, SupportedAlgs: []string{"RS256"}},
		"b": {Issuer: "https://dup", Audiences: []string{"y"}, SupportedAlgs: []string{"RS256"}},
	}, sharedJWKSClient{})
	assert.NotContains(t, r.failed, "a")
	assert.ErrorContains(t, r.failed["b"], `issuer "https://dup" used by both "a" and "b"`)

	rp, err := r.resolveUnverified(t.Context(),
		encodeUnsignedJWT(t, map[string]any{"iss": "https://dup"}))
	require.NoError(t, err)
	assert.Equal(t, "a", rp.Name)
}

func TestNewIdentityProviderResolver_InvalidProviderName(t *testing.T) {
	t.Parallel()
	// A name containing '/' would break the "<provider>/<sub>" user-id split.
	r := newIdentityProviderResolver(t.Context(), map[string]IdentityProvider{
		"k8s/prod": {Issuer: "https://a", Audiences: []string{"x"}, SupportedAlgs: []string{"RS256"}},
		"good":     {Issuer: "https://b", Audiences: []string{"x"}, SupportedAlgs: []string{"RS256"}},
	}, sharedJWKSClient{})
	require.Error(t, r.failed["k8s/prod"])
	assert.NotContains(t, r.failed, "good")

	rp, err := r.resolveUnverified(t.Context(),
		encodeUnsignedJWT(t, map[string]any{"iss": "https://b"}))
	require.NoError(t, err)
	assert.Equal(t, "good", rp.Name)

	// A miss says which providers are unusable, so a deny log distinguishes
	// "never configured" from "the one that would have matched is broken".
	_, err = r.resolveUnverified(t.Context(),
		encodeUnsignedJWT(t, map[string]any{"iss": "https://a"}))
	require.ErrorIs(t, err, ErrNoMatchingIdentityProvider)
	assert.ErrorContains(t, err, "k8s/prod")
}

func TestIdentityProviderResolver_Verify(t *testing.T) {
	t.Parallel()

	idp := mockidp.New(mockidp.Config{})
	issuer := idp.Start(t)

	resolver := newIdentityProviderResolver(t.Context(), map[string]IdentityProvider{
		"k8s": {Issuer: issuer, Audiences: []string{"pomerium.example.com"}, SupportedAlgs: []string{"ES256"}},
	}, sharedJWKSClient{})

	now := time.Now()
	tok := idp.SignJWT(map[string]any{
		"iss": issuer,
		"sub": "system:serviceaccount:ns:sa",
		"aud": []string{"pomerium.example.com"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	})

	t.Run("happy path returns provider name", func(t *testing.T) {
		res, err := resolver.Verify(t.Context(), tok)
		require.NoError(t, err)
		assert.Equal(t, "k8s", res.ProviderName)
		assert.Equal(t, "system:serviceaccount:ns:sa", res.Claims["sub"])
	})

	t.Run("untrusted issuer", func(t *testing.T) {
		other := mockidp.New(mockidp.Config{})
		otherIssuer := other.Start(t)
		otherTok := other.SignJWT(map[string]any{
			"iss": otherIssuer,
			"aud": []string{"pomerium.example.com"},
			"exp": now.Add(time.Hour).Unix(),
		})
		_, err := resolver.Verify(t.Context(), otherTok)
		assert.ErrorIs(t, err, ErrNoMatchingIdentityProvider)
	})

	t.Run("wrong audience for provider", func(t *testing.T) {
		wrongAud := idp.SignJWT(map[string]any{
			"iss": issuer,
			"sub": "x",
			"aud": []string{"someone-else"},
			"exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
		})
		_, err := resolver.Verify(t.Context(), wrongAud)
		require.ErrorIs(t, err, extjwt.ErrAudienceMismatch)
		require.NotErrorIs(t, err, ErrNoMatchingIdentityProvider)
	})

	t.Run("garbage token", func(t *testing.T) {
		_, err := resolver.Verify(t.Context(), "not.a.jwt")
		require.Error(t, err)
	})
}

// TestIdentityProviderResolver_ResolveUnverified pins the unverified dispatch:
// it maps a token's iss to a provider without any signature/audience check.
func TestIdentityProviderResolver_ResolveUnverified(t *testing.T) {
	t.Parallel()

	provider := IdentityProvider{Issuer: "https://k8s.example.com", Audiences: []string{"pomerium"}, SupportedAlgs: []string{"RS256"}}
	resolver := newIdentityProviderResolver(t.Context(), map[string]IdentityProvider{
		"k8s": provider,
	}, sharedJWKSClient{})

	// A syntactically-valid but unsigned token is enough — the dispatch never
	// verifies the signature.
	known := encodeUnsignedJWT(t, map[string]any{"iss": "https://k8s.example.com", "sub": "x"})
	rp, err := resolver.resolveUnverified(t.Context(), known)
	require.NoError(t, err)
	assert.Equal(t, "k8s", rp.Name)

	unknown := encodeUnsignedJWT(t, map[string]any{"iss": "https://other.example.com"})
	_, err = resolver.resolveUnverified(t.Context(), unknown)
	assert.ErrorIs(t, err, ErrNoMatchingIdentityProvider)

	_, err = resolver.resolveUnverified(t.Context(), "not-a-jwt")
	require.Error(t, err)
}

// derivedCAPEM returns a self-signed CA certificate PEM derived from psk.
func derivedCAPEM(t testing.TB, psk string) []byte {
	t.Helper()
	ca, err := derivecert.NewCA([]byte(psk))
	require.NoError(t, err)
	p, err := ca.PEM()
	require.NoError(t, err)
	return p.Cert
}

// TestNewIdentityProviderResolverFromConfig pins the reuse gate: a resolver (and
// with it the JWKS cache behind it) survives configuration changes that do not
// concern identity providers, and is rebuilt when any input to it changes.
func TestNewIdentityProviderResolverFromConfig(t *testing.T) {
	t.Parallel()

	providers := func() map[string]IdentityProvider {
		return map[string]IdentityProvider{
			"k8s": {Issuer: "https://k8s.example.com", Audiences: []string{"pomerium"}, SupportedAlgs: []string{"RS256"}},
		}
	}

	t.Run("no providers configured", func(t *testing.T) {
		r := NewIdentityProviderResolverFromConfig(t.Context(), New(&Options{}), nil)
		assert.Nil(t, r, "no providers configured -> nil resolver")
	})

	t.Run("reused when unchanged", func(t *testing.T) {
		cfg := New(&Options{IdentityProviders: providers()})
		r1 := NewIdentityProviderResolverFromConfig(t.Context(), cfg, nil)
		require.NotNil(t, r1)

		r2 := NewIdentityProviderResolverFromConfig(t.Context(), cfg, r1)
		assert.Same(t, r1, r2)
	})

	t.Run("reused across an unrelated configuration change", func(t *testing.T) {
		r1 := NewIdentityProviderResolverFromConfig(t.Context(),
			New(&Options{IdentityProviders: providers()}), nil)

		// A new generation that changes something the resolver does not depend on
		// must not discard it: rebuilding would drop the JWKS cache.
		next := New(&Options{IdentityProviders: providers(), CookieExpire: time.Hour})
		r2 := NewIdentityProviderResolverFromConfig(t.Context(), next, r1)
		assert.Same(t, r1, r2)
	})

	t.Run("rebuilt when the provider set changes", func(t *testing.T) {
		r1 := NewIdentityProviderResolverFromConfig(t.Context(),
			New(&Options{IdentityProviders: providers()}), nil)
		require.NotNil(t, r1)

		for _, tc := range []struct {
			name   string
			mutate func(map[string]IdentityProvider)
		}{
			{"provider added", func(m map[string]IdentityProvider) {
				m["other"] = IdentityProvider{Issuer: "https://other.example.com", Audiences: []string{"pomerium"}}
			}},
			{"provider removed", func(m map[string]IdentityProvider) {
				delete(m, "k8s")
			}},
			{"issuer changed", func(m map[string]IdentityProvider) {
				p := m["k8s"]
				p.Issuer = "https://k8s2.example.com"
				m["k8s"] = p
			}},
			{"audiences narrowed", func(m map[string]IdentityProvider) {
				p := m["k8s"]
				p.Audiences = []string{"other"}
				m["k8s"] = p
			}},
			{"supported algs changed", func(m map[string]IdentityProvider) {
				p := m["k8s"]
				p.SupportedAlgs = []string{"ES256"}
				m["k8s"] = p
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				next := providers()
				tc.mutate(next)
				r2 := NewIdentityProviderResolverFromConfig(t.Context(),
					New(&Options{IdentityProviders: next}), r1)
				assert.NotSame(t, r1, r2)
			})
		}
	})

	// certificate_authority_file is watched, so rotating it in place produces a
	// reload whose Options are byte-identical. The resolver must still be rebuilt
	// or it would keep trusting the old CA for JWKS/discovery fetches.
	t.Run("rebuilt when the CA file contents change", func(t *testing.T) {
		// Distinct PSKs derive distinct CAs; httptest's TLS servers all share one
		// hardcoded certificate, so they cannot stand in here.
		caFile := filepath.Join(t.TempDir(), "ca.pem")
		writeCA := func(psk string) {
			require.NoError(t, os.WriteFile(caFile, derivedCAPEM(t, psk), 0o600))
		}

		writeCA("psk-1")
		cfg := New(&Options{IdentityProviders: providers(), CAFile: caFile})
		r1 := NewIdentityProviderResolverFromConfig(t.Context(), cfg, nil)
		require.NotNil(t, r1)

		writeCA("psk-2") // same path, different CA
		r2 := NewIdentityProviderResolverFromConfig(t.Context(), cfg, r1)
		assert.NotSame(t, r1, r2)
	})

	// A degraded resolver carries no cache key, so the next generation rebuilds it
	// rather than reusing a provider whose failure may since have been fixed.
	t.Run("degraded build is retried", func(t *testing.T) {
		bad := New(&Options{IdentityProviders: providers(), CA: "@@@not-valid-base64-or-pem@@@"})
		r1 := NewIdentityProviderResolverFromConfig(t.Context(), bad, nil)
		require.NotNil(t, r1)
		require.Error(t, r1.failed["k8s"], "a CA that fails to load disables the providers using it")
		assert.Zero(t, r1.cacheKey)

		good := New(&Options{IdentityProviders: providers()})
		r2 := NewIdentityProviderResolverFromConfig(t.Context(), good, r1)
		require.NotSame(t, r1, r2)
		assert.Empty(t, r2.failed)
	})

	// A zero key would make every resolver look reusable.
	t.Run("cache key is non-zero", func(t *testing.T) {
		key, err := New(&Options{IdentityProviders: providers()}).identityProviderResolverCacheKey()
		require.NoError(t, err)
		assert.NotZero(t, key)
	})
}

// TestIdentityProviderResolver_HealthChecks: a degraded provider is only visible
// in a log line otherwise, so each one publishes its own check. Not parallel — it
// asserts against the process-global health registry.
func TestIdentityProviderResolver_HealthChecks(t *testing.T) {
	healthy := health.IdentityProvider("healthcheck-good")
	broken := health.IdentityProvider("healthcheck-bad")

	providers := map[string]IdentityProvider{
		"healthcheck-good": {Issuer: "https://good.example.com", Audiences: []string{"pomerium"}},
		// No audiences: rejected by IdentityProvider.Validate, and by itself.
		"healthcheck-bad": {Issuer: "https://bad.example.com"},
		// Resolved on the dispatch path, so nothing is known about it yet.
		"healthcheck-k8s": {Issuer: "kubernetes:///", Audiences: []string{"pomerium"}},
	}
	r := NewIdentityProviderResolverFromConfig(t.Context(),
		New(&Options{IdentityProviders: providers}), nil)
	require.NotNil(t, r)

	records := health.GetProviderManager().GetRecords()
	require.Contains(t, records, healthy)
	require.Contains(t, records, broken)
	assert.Equal(t, health.StatusRunning, records[healthy].Status())
	assert.NoError(t, records[healthy].Err())
	assert.ErrorContains(t, records[broken].Err(), "at least one audience is required")

	// Reporting a kubernetes:/// provider healthy before it has resolved anything
	// would assert a fact nobody established — and would silently clear a standing
	// error every time the configuration changed, since each generation builds a
	// fresh provider with no memory of the last failure.
	assert.NotContains(t, records, health.IdentityProvider("healthcheck-k8s"),
		"a provider that has not resolved yet must report nothing")

	// Removing a provider must retract its check: nothing else ever would, and a
	// stale error would keep the process looking unhealthy for its lifetime.
	t.Run("a removed provider's check is retracted", func(t *testing.T) {
		next := New(&Options{IdentityProviders: map[string]IdentityProvider{
			"healthcheck-good": providers["healthcheck-good"],
		}})
		require.NotNil(t, NewIdentityProviderResolverFromConfig(t.Context(), next, r))

		records := health.GetProviderManager().GetRecords()
		assert.NoError(t, records[broken].Err())
		assert.Equal(t, health.StatusTerminating, records[broken].Status())
		assert.Equal(t, health.StatusRunning, records[healthy].Status())
	})
}

// TestIdentityProviderResolver_CustomCA verifies that the resolver built for a
// Config wires the global certificate_authority into the JWKS/discovery HTTP
// client: a self-signed issuer verifies only when its CA is trusted.
func TestIdentityProviderResolver_CustomCA(t *testing.T) {
	t.Parallel()

	idp := mockidp.New(mockidp.Config{})
	router := mux.NewRouter()
	idp.Register(router)
	srv := httptest.NewTLSServer(router)
	t.Cleanup(srv.Close)

	issuer := srv.URL
	now := time.Now()
	tok := idp.SignJWT(map[string]any{
		"iss": issuer,
		"sub": "sa",
		"aud": []string{"pomerium"},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
	})

	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	caB64 := base64.StdEncoding.EncodeToString(caPEM)

	providers := map[string]IdentityProvider{
		"k8s": {Issuer: issuer, Audiences: []string{"pomerium"}, SupportedAlgs: []string{"ES256"}},
	}

	t.Run("with CA verifies", func(t *testing.T) {
		cfg := New(&Options{CA: caB64, IdentityProviders: providers})
		resolver := NewIdentityProviderResolverFromConfig(t.Context(), cfg, nil)
		require.NotNil(t, resolver)
		res, err := resolver.Verify(t.Context(), tok)
		require.NoError(t, err)
		assert.Equal(t, "k8s", res.ProviderName)
	})

	t.Run("without CA fails on TLS", func(t *testing.T) {
		cfg := New(&Options{IdentityProviders: providers})
		resolver := NewIdentityProviderResolverFromConfig(t.Context(), cfg, nil)
		require.NotNil(t, resolver)
		_, err := resolver.Verify(t.Context(), tok)
		require.Error(t, err)
	})
}

// TestIdentityProviderResolver_BadCASurfacesError verifies that an explicitly
// configured certificate_authority that fails to load disables the providers that
// would have used it, rather than silently falling back to system roots. Falling
// back would make the intended private-CA issuer's JWKS/discovery fetch fail with
// "unknown authority" and reject every token, with only a single startup log line.
//
// The blast radius stops there: a kubernetes:// provider trusts the cluster CA
// through its own client and keeps working.
func TestIdentityProviderResolver_BadCASurfacesError(t *testing.T) {
	t.Parallel()

	providers := map[string]IdentityProvider{
		"k8s":     {Issuer: "https://issuer.example.com", Audiences: []string{"aud"}, SupportedAlgs: []string{"ES256"}},
		"cluster": {Issuer: "kubernetes:///", Audiences: []string{"aud"}, SupportedAlgs: []string{"ES256"}},
	}
	// certificate_authority is set but malformed (not valid base64-encoded PEM).
	cfg := New(&Options{CA: "@@@not-valid-base64-or-pem@@@", IdentityProviders: providers})

	r := NewIdentityProviderResolverFromConfig(t.Context(), cfg, nil)
	require.NotNil(t, r)
	assert.ErrorContains(t, r.failed["k8s"], "error building CA cert pool")
	assert.NotContains(t, r.failed, "cluster")
	assert.Len(t, r.deferred, 1)

	// The failure is reported on the tokens it affects, naming itself.
	_, err := r.resolveUnverified(t.Context(),
		encodeUnsignedJWT(t, map[string]any{"iss": "https://issuer.example.com"}))
	require.ErrorIs(t, err, ErrNoMatchingIdentityProvider)
	assert.ErrorContains(t, err, "identity_providers[k8s]")
}
