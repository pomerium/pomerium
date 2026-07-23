package authorize

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc"
)

// TestNewAuthorizeStateFromConfig_IdentityProviderResolverReuse pins that the
// state builder hands the previous generation's resolver to the next one, so the
// JWKS cache behind it survives a configuration change that does not concern
// identity providers. The reuse gate itself is
// covered by config.TestNewIdentityProviderResolverFromConfig.
func TestNewAuthorizeStateFromConfig_IdentityProviderResolverReuse(t *testing.T) {
	t.Parallel()

	newOptions := func(providers map[string]config.IdentityProvider) *config.Options {
		return &config.Options{
			AuthenticateURLString: "https://authN.example.com",
			DataBroker:            config.DataBrokerOptions{ServiceURL: "https://databroker.example.com"},
			CookieSecret:          "15WXae6fvK9Hal0RGZ600JlCaflYHtNy9bAyOLTlvmc=",
			SharedKey:             "2p/Wi2Q6bYDfzmoSEbKqYKtg+DUoLWTEHHs7vOhvL7w=",
			Policies:              testPolicies(t),
			IdentityProviders:     providers,
		}
	}
	providers := map[string]config.IdentityProvider{
		"k8s": {Issuer: "https://k8s.example.com", Audiences: []string{"pomerium"}, SupportedAlgs: []string{"RS256"}},
	}
	newState := func(t *testing.T, previous *authorizeState, opts *config.Options) *authorizeState {
		t.Helper()
		state, err := newAuthorizeStateFromConfig(t.Context(), previous, noop.NewTracerProvider(),
			config.New(opts), store.New(), nil, new(grpc.CachedOutboundGRPClientConn))
		require.NoError(t, err)
		return state
	}

	first := newState(t, nil, newOptions(providers))
	require.NotNil(t, first.idpResolver)

	opts := newOptions(providers)
	opts.CookieExpire = time.Hour
	assert.Same(t, first.idpResolver, newState(t, first, opts).idpResolver)
}
