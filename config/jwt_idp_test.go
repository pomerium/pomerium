package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil/mockidp"
)

func TestJWTIdentityProvider_Validate(t *testing.T) {
	t.Parallel()
	t.Run("missing name", func(t *testing.T) {
		err := (&JWTIdentityProvider{Issuer: "https://example.com"}).Validate()
		assert.Error(t, err)
	})
	t.Run("missing issuer", func(t *testing.T) {
		err := (&JWTIdentityProvider{Name: "n"}).Validate()
		assert.Error(t, err)
	})
	t.Run("bad jwks scheme", func(t *testing.T) {
		err := (&JWTIdentityProvider{Name: "n", Issuer: "https://x", JWKSURL: "ftp://bad"}).Validate()
		assert.Error(t, err)
	})
	t.Run("ok", func(t *testing.T) {
		err := (&JWTIdentityProvider{Name: "n", Issuer: "https://x", JWKSURL: "https://x/jwks"}).Validate()
		assert.NoError(t, err)
	})
}

func TestJWTIdpAcceptance_Validate(t *testing.T) {
	t.Parallel()
	t.Run("missing name", func(t *testing.T) {
		err := (&JWTIdpAcceptance{Audiences: []string{"a"}}).Validate()
		assert.Error(t, err)
	})
	t.Run("missing audiences", func(t *testing.T) {
		err := (&JWTIdpAcceptance{Name: "n"}).Validate()
		assert.Error(t, err)
	})
	t.Run("ok", func(t *testing.T) {
		err := (&JWTIdpAcceptance{Name: "n", Audiences: []string{"a"}}).Validate()
		assert.NoError(t, err)
	})
}

func TestNewJWTIdpResolver_DuplicateName(t *testing.T) {
	t.Parallel()
	_, err := NewJWTIdpResolver([]JWTIdentityProvider{
		{Name: "x", Issuer: "https://a", SupportedAlgs: []string{"RS256"}},
		{Name: "x", Issuer: "https://b", SupportedAlgs: []string{"RS256"}},
	})
	require.Error(t, err)
}

func TestJWTIdpResolver_VerifyForPolicy(t *testing.T) {
	t.Parallel()

	idp := mockidp.New(mockidp.Config{})
	issuer := idp.Start(t)

	resolver, err := NewJWTIdpResolver([]JWTIdentityProvider{
		{Name: "test", Issuer: issuer, SupportedAlgs: []string{"ES256"}},
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
		accept := []JWTIdpAcceptance{{Name: "test", Audiences: []string{"pomerium.example.com"}}}
		res, err := resolver.VerifyForPolicy(t.Context(), accept, tok)
		require.NoError(t, err)
		assert.Equal(t, "test", res.ProviderName)
		assert.Equal(t, "system:serviceaccount:ns:sa", res.Claims["sub"])
	})

	t.Run("no acceptance entries", func(t *testing.T) {
		_, err := resolver.VerifyForPolicy(t.Context(), nil, tok)
		assert.ErrorIs(t, err, ErrNoMatchingJWTIdp)
	})

	t.Run("unknown provider name on route", func(t *testing.T) {
		accept := []JWTIdpAcceptance{{Name: "other", Audiences: []string{"pomerium.example.com"}}}
		_, err := resolver.VerifyForPolicy(t.Context(), accept, tok)
		assert.ErrorIs(t, err, ErrNoMatchingJWTIdp)
	})

	t.Run("wrong audience", func(t *testing.T) {
		accept := []JWTIdpAcceptance{{Name: "test", Audiences: []string{"other.example.com"}}}
		_, err := resolver.VerifyForPolicy(t.Context(), accept, tok)
		require.Error(t, err)
	})

	t.Run("garbage token", func(t *testing.T) {
		accept := []JWTIdpAcceptance{{Name: "test", Audiences: []string{"pomerium.example.com"}}}
		_, err := resolver.VerifyForPolicy(t.Context(), accept, "not.a.jwt")
		require.Error(t, err)
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
