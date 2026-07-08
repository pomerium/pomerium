package config

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOptions_RoundTripPreservesIdentityProviders ensures identity-provider
// config survives the Options → proto Settings → Options round trip used by
// Pomerium's internal config-reload path.
func TestOptions_RoundTripPreservesIdentityProviders(t *testing.T) {
	t.Parallel()

	src := NewDefaultOptions()
	src.IdentityProviders = map[string]IdentityProvider{
		"k8s-prod": {
			Issuer:        "https://kubernetes.default.svc.cluster.local",
			JWKSURL:       "https://kube-jwks.internal/openid/v1/jwks",
			SupportedAlgs: []string{"RS256"},
			Audiences:     []string{"pomerium"},
		},
	}

	pb := src.ToProto()
	require.NotNil(t, pb)
	require.NotNil(t, pb.Settings)
	require.Len(t, pb.Settings.IdentityProviders, 1, "ToProto must emit identity providers")

	dst := NewDefaultOptions()
	dst.ApplySettings(context.Background(), nil, pb.Settings)

	require.Equal(t, src.IdentityProviders, dst.IdentityProviders)
}
