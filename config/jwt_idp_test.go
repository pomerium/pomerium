package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
