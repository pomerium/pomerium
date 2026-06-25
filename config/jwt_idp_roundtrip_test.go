package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOptions_RoundTripPreservesJWTIdps ensures that JWT IdP config survives
// the Options → proto Settings → Options round trip (used by Pomerium's
// internal config-reload path).
func TestOptions_RoundTripPreservesJWTIdps(t *testing.T) {
	t.Parallel()

	src := NewDefaultOptions()
	src.JWTIdentityProviders = []JWTIdentityProvider{
		{
			Name:          "k8s-prod",
			Issuer:        "https://oidc.eks.example.com",
			JWKSURL:       "https://oidc.eks.example.com/keys",
			SupportedAlgs: []string{"RS256"},
		},
	}

	pb := src.ToProto()
	require.NotNil(t, pb)
	require.NotNil(t, pb.Settings)
	require.Len(t, pb.Settings.JwtIdentityProviders, 1, "ToProto must emit JWT IdPs")

	dst := NewDefaultOptions()
	dst.ApplySettings(context.Background(), nil, pb.Settings)

	require.Len(t, dst.JWTIdentityProviders, 1, "ApplySettings must restore JWT IdPs")
	got := dst.JWTIdentityProviders[0]
	require.Equal(t, "k8s-prod", got.Name)
	require.Equal(t, "https://oidc.eks.example.com", got.Issuer)
	require.Equal(t, "https://oidc.eks.example.com/keys", got.JWKSURL)
	require.Equal(t, []string{"RS256"}, got.SupportedAlgs)
}
