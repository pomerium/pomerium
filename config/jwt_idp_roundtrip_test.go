package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOptions_RoundTripPreservesJWTIssuers ensures that JWT issuer + audience
// config survives the Options → proto Settings → Options round trip (used by
// Pomerium's internal config-reload path).
func TestOptions_RoundTripPreservesJWTIssuers(t *testing.T) {
	t.Parallel()

	src := NewDefaultOptions()
	src.JWTAllowedIssuers = []JWTAllowedIssuer{
		{
			Issuer:        "https://oidc.eks.example.com",
			JWKSURL:       "https://oidc.eks.example.com/keys",
			SupportedAlgs: []string{"RS256"},
			Name:          "k8s-prod",
		},
	}
	audiences := []string{"pomerium.api"}
	src.JWTAllowedAudiences = &audiences

	pb := src.ToProto()
	require.NotNil(t, pb)
	require.NotNil(t, pb.Settings)
	require.Len(t, pb.Settings.JwtAllowedIssuers, 1, "ToProto must emit JWT issuers")
	require.NotNil(t, pb.Settings.JwtAllowedAudiences, "ToProto must emit JWT audiences")

	dst := NewDefaultOptions()
	dst.ApplySettings(context.Background(), nil, pb.Settings)

	require.Len(t, dst.JWTAllowedIssuers, 1, "ApplySettings must restore JWT issuers")
	got := dst.JWTAllowedIssuers[0]
	require.Equal(t, "https://oidc.eks.example.com", got.Issuer)
	require.Equal(t, "https://oidc.eks.example.com/keys", got.JWKSURL)
	require.Equal(t, []string{"RS256"}, got.SupportedAlgs)
	require.Equal(t, "k8s-prod", got.Name)

	require.NotNil(t, dst.JWTAllowedAudiences)
	require.Equal(t, []string{"pomerium.api"}, *dst.JWTAllowedAudiences)
}
