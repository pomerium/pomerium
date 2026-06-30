package config

import (
	"encoding/base64"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"hegel.dev/go/hegel"

	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestJWTAllowedIssuer_Validate(t *testing.T) {
	t.Parallel()
	t.Run("missing issuer", func(t *testing.T) {
		err := (&JWTAllowedIssuer{}).Validate()
		assert.Error(t, err)
	})
	t.Run("bad jwks scheme", func(t *testing.T) {
		err := (&JWTAllowedIssuer{Issuer: "https://x", JWKSURL: "ftp://bad"}).Validate()
		assert.Error(t, err)
	})
	t.Run("ok", func(t *testing.T) {
		err := (&JWTAllowedIssuer{Issuer: "https://x", JWKSURL: "https://x/jwks"}).Validate()
		assert.NoError(t, err)
	})
}

func TestNewJWTIssuerResolver_DuplicateIssuer(t *testing.T) {
	t.Parallel()
	_, err := NewJWTIssuerResolver([]JWTAllowedIssuer{
		{Issuer: "https://a", SupportedAlgs: []string{"RS256"}},
		{Issuer: "https://a", SupportedAlgs: []string{"RS256"}},
	})
	require.Error(t, err)
}

func TestJWTIssuerResolver_Verify(t *testing.T) {
	t.Parallel()

	idp := mockidp.New(mockidp.Config{})
	issuer := idp.Start(t)

	resolver, err := NewJWTIssuerResolver([]JWTAllowedIssuer{
		{Issuer: issuer, SupportedAlgs: []string{"ES256"}},
	})
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

	t.Run("happy path", func(t *testing.T) {
		res, err := resolver.Verify(t.Context(), tok, []string{"pomerium.example.com"})
		require.NoError(t, err)
		assert.Equal(t, issuer, res.Issuer)
		assert.Equal(t, "system:serviceaccount:ns:sa", res.Claims["sub"])
	})

	t.Run("empty audiences (fail-closed)", func(t *testing.T) {
		_, err := resolver.Verify(t.Context(), tok, nil)
		require.Error(t, err)
	})

	t.Run("untrusted issuer", func(t *testing.T) {
		other := mockidp.New(mockidp.Config{})
		otherIssuer := other.Start(t)
		otherTok := other.SignJWT(map[string]any{
			"iss": otherIssuer,
			"aud": []string{"pomerium.example.com"},
			"exp": now.Add(time.Hour).Unix(),
		})
		_, err := resolver.Verify(t.Context(), otherTok, []string{"pomerium.example.com"})
		assert.ErrorIs(t, err, ErrNoMatchingJWTIssuer)
	})

	t.Run("wrong audience", func(t *testing.T) {
		_, err := resolver.Verify(t.Context(), tok, []string{"other.example.com"})
		require.Error(t, err)
	})

	t.Run("garbage token", func(t *testing.T) {
		_, err := resolver.Verify(t.Context(), "not.a.jwt", []string{"pomerium.example.com"})
		require.Error(t, err)
	})
}

func TestValidateJWTBearerTokens(t *testing.T) {
	t.Parallel()

	jwtFmt := configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT
	issuers := []JWTAllowedIssuer{{Issuer: "https://issuer.example.com", SupportedAlgs: []string{"RS256"}}}
	auds := []string{"pomerium.api"}

	jwtRoute := func() Policy {
		return Policy{RouteOptions: RouteOptions{BearerTokenFormat: nullable.From(jwtFmt)}}
	}

	t.Run("jwt route requires issuers", func(t *testing.T) {
		o := NewDefaultOptions()
		r := jwtRoute()
		r.JWTAllowedAudiences = &auds
		o.Policies = []Policy{r}
		assert.Error(t, o.validateJWTBearerTokens())
	})

	t.Run("jwt route requires audiences", func(t *testing.T) {
		o := NewDefaultOptions()
		o.JWTAllowedIssuers = issuers
		o.Policies = []Policy{jwtRoute()}
		assert.Error(t, o.validateJWTBearerTokens())
	})

	t.Run("jwt route with route-level audiences ok", func(t *testing.T) {
		o := NewDefaultOptions()
		o.JWTAllowedIssuers = issuers
		r := jwtRoute()
		r.JWTAllowedAudiences = &auds
		o.Policies = []Policy{r}
		assert.NoError(t, o.validateJWTBearerTokens())
	})

	t.Run("jwt route with global audiences ok", func(t *testing.T) {
		o := NewDefaultOptions()
		o.JWTAllowedIssuers = issuers
		o.JWTAllowedAudiences = &auds
		o.Policies = []Policy{jwtRoute()}
		assert.NoError(t, o.validateJWTBearerTokens())
	})

	t.Run("duplicate issuers rejected", func(t *testing.T) {
		o := NewDefaultOptions()
		o.JWTAllowedIssuers = []JWTAllowedIssuer{
			{Issuer: "https://issuer.example.com", SupportedAlgs: []string{"RS256"}},
			{Issuer: "https://issuer.example.com", SupportedAlgs: []string{"RS256"}},
		}
		assert.Error(t, o.validateJWTBearerTokens())
	})

	t.Run("non-jwt route needs nothing", func(t *testing.T) {
		o := NewDefaultOptions()
		o.Policies = []Policy{{}}
		assert.NoError(t, o.validateJWTBearerTokens())
	})
}

func TestUnverifiedIssuer(t *testing.T) {
	t.Parallel()

	idp := mockidp.New(mockidp.Config{})
	idp.Start(t)

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
func encodeUnsignedJWT(t *testing.T, claims map[string]any) string {
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
// diverges from what was in the token, the wrong trusted issuer (and thus the
// wrong signing keys / verifier) could be selected.
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

// TestJWTAllowedIssuers_ProtoRoundTrip checks that a non-empty slice of trusted
// issuers survives the Options-struct <-> proto conversion used by the
// config-reload path. A field dropped or reordered here silently changes which
// issuers/keys/algs Pomerium will trust.
func TestJWTAllowedIssuers_ProtoRoundTrip(t *testing.T) {
	t.Parallel()
	hegel.Test(t, func(ht *hegel.T) {
		n := hegel.Draw(ht, hegel.Integers(1, 6))
		src := make([]JWTAllowedIssuer, 0, n)
		for range n {
			src = append(src, JWTAllowedIssuer{
				Issuer:        hegel.Draw(ht, hegel.Text().MaxSize(40)),
				JWKSURL:       hegel.Draw(ht, hegel.Text().MaxSize(40)),
				SupportedAlgs: hegel.Draw(ht, hegel.Lists(hegel.Text().MaxSize(10)).MaxSize(5)),
				Name:          hegel.Draw(ht, hegel.Text().MaxSize(20)),
			})
		}

		var dst []JWTAllowedIssuer
		setJWTAllowedIssuers(&dst, jwtAllowedIssuersToProto(src))

		if len(dst) != len(src) {
			ht.Fatalf("length changed: got %d want %d", len(dst), len(src))
		}
		for i := range src {
			if dst[i].Issuer != src[i].Issuer {
				ht.Fatalf("issuer[%d] mismatch: got %q want %q", i, dst[i].Issuer, src[i].Issuer)
			}
			if dst[i].JWKSURL != src[i].JWKSURL {
				ht.Fatalf("jwks_url[%d] mismatch: got %q want %q", i, dst[i].JWKSURL, src[i].JWKSURL)
			}
			if dst[i].Name != src[i].Name {
				ht.Fatalf("name[%d] mismatch: got %q want %q", i, dst[i].Name, src[i].Name)
			}
			// nil and empty are equivalent ("use defaults"); slices.Equal treats them so.
			if !slices.Equal(dst[i].SupportedAlgs, src[i].SupportedAlgs) {
				ht.Fatalf("supported_algs[%d] mismatch: got %v want %v", i, dst[i].SupportedAlgs, src[i].SupportedAlgs)
			}
		}
	})
}
