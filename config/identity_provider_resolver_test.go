package config

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hegel.dev/go/hegel"

	"github.com/pomerium/pomerium/internal/testutil/mockidp"
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

func TestNewIdentityProviderResolver_DuplicateIssuer(t *testing.T) {
	t.Parallel()
	_, err := NewIdentityProviderResolver(map[string]IdentityProvider{
		"a": {Issuer: "https://dup", Audiences: []string{"x"}, SupportedAlgs: []string{"RS256"}},
		"b": {Issuer: "https://dup", Audiences: []string{"y"}, SupportedAlgs: []string{"RS256"}},
	}, nil)
	require.Error(t, err)
}

func TestNewIdentityProviderResolver_InvalidProviderName(t *testing.T) {
	t.Parallel()
	// A name containing '/' would break the "<provider>/<sub>" user-id split.
	_, err := NewIdentityProviderResolver(map[string]IdentityProvider{
		"k8s/prod": {Issuer: "https://a", Audiences: []string{"x"}, SupportedAlgs: []string{"RS256"}},
	}, nil)
	require.Error(t, err)
}

func TestIdentityProviderResolver_Verify(t *testing.T) {
	t.Parallel()

	idp := mockidp.New(mockidp.Config{})
	issuer := idp.Start(t)

	resolver, err := NewIdentityProviderResolver(map[string]IdentityProvider{
		"k8s": {Issuer: issuer, Audiences: []string{"pomerium.example.com"}, SupportedAlgs: []string{"ES256"}},
	}, nil)
	require.NoError(t, err)

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

// TestIdentityProviderResolver_ResolveName pins the unverified dispatch: it maps
// a token's iss to a provider name without any signature/audience check.
func TestIdentityProviderResolver_ResolveName(t *testing.T) {
	t.Parallel()

	resolver, err := NewIdentityProviderResolver(map[string]IdentityProvider{
		"k8s": {Issuer: "https://k8s.example.com", Audiences: []string{"pomerium"}, SupportedAlgs: []string{"RS256"}},
	}, nil)
	require.NoError(t, err)

	// A syntactically-valid but unsigned token is enough — ResolveName never
	// verifies the signature.
	known := encodeUnsignedJWT(t, map[string]any{"iss": "https://k8s.example.com", "sub": "x"})
	name, err := resolver.ResolveName(known)
	require.NoError(t, err)
	assert.Equal(t, "k8s", name)

	unknown := encodeUnsignedJWT(t, map[string]any{"iss": "https://other.example.com"})
	_, err = resolver.ResolveName(unknown)
	assert.ErrorIs(t, err, ErrNoMatchingIdentityProvider)

	_, err = resolver.ResolveName("not-a-jwt")
	require.Error(t, err)
}

func TestConfig_IdentityProviderResolver_Memoized(t *testing.T) {
	t.Parallel()

	cfg := New(&Options{IdentityProviders: map[string]IdentityProvider{
		"k8s": {Issuer: "https://k8s.example.com", Audiences: []string{"pomerium"}, SupportedAlgs: []string{"RS256"}},
	}})
	r1, err := cfg.IdentityProviderResolver()
	require.NoError(t, err)
	require.NotNil(t, r1)
	r2, err := cfg.IdentityProviderResolver()
	require.NoError(t, err)
	assert.Same(t, r1, r2, "resolver must be built once and cached")

	empty := New(&Options{})
	r3, err := empty.IdentityProviderResolver()
	require.NoError(t, err)
	assert.Nil(t, r3, "no providers configured -> nil resolver")
}

// TestIdentityProviderResolver_CustomCA verifies that cfg.IdentityProviderResolver
// wires the global certificate_authority into the JWKS/discovery HTTP client: a
// self-signed issuer verifies only when its CA is trusted.
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
		resolver, err := cfg.IdentityProviderResolver()
		require.NoError(t, err)
		require.NotNil(t, resolver)
		res, err := resolver.Verify(t.Context(), tok)
		require.NoError(t, err)
		assert.Equal(t, "k8s", res.ProviderName)
	})

	t.Run("without CA fails on TLS", func(t *testing.T) {
		cfg := New(&Options{IdentityProviders: providers})
		resolver, err := cfg.IdentityProviderResolver()
		require.NoError(t, err)
		require.NotNil(t, resolver)
		_, err = resolver.Verify(t.Context(), tok)
		require.Error(t, err)
	})
}

// TestIdentityProviderResolver_BadCASurfacesError verifies that an explicitly
// configured certificate_authority that fails to load is a hard error, not a
// silent fallback to system roots. Falling back would make the intended
// private-CA issuer's JWKS/discovery fetch fail with "unknown authority" and
// silently reject every token, with only a single startup log line.
func TestIdentityProviderResolver_BadCASurfacesError(t *testing.T) {
	t.Parallel()

	providers := map[string]IdentityProvider{
		"k8s": {Issuer: "https://issuer.example.com", Audiences: []string{"aud"}, SupportedAlgs: []string{"ES256"}},
	}
	// certificate_authority is set but malformed (not valid base64-encoded PEM).
	cfg := New(&Options{CA: "@@@not-valid-base64-or-pem@@@", IdentityProviders: providers})

	_, err := cfg.IdentityProviderResolver()
	require.Error(t, err)
}
