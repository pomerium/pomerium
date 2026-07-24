package proxy

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

// TestNewProxyStateFromConfig_IdentityProviderResolver covers the resolver the
// proxy owns for the user-info page's bearer-token path: it must be wired into
// the session creator, and it must survive configuration changes that do not
// concern identity providers.
func TestNewProxyStateFromConfig_IdentityProviderResolver(t *testing.T) {
	t.Parallel()

	providers := map[string]config.IdentityProvider{
		"k8s": {Issuer: "https://k8s.example.com", Audiences: []string{"pomerium"}, SupportedAlgs: []string{"RS256"}},
	}
	newOptions := func(t *testing.T, ps map[string]config.IdentityProvider) *config.Options {
		t.Helper()
		opts := testOptions(t)
		opts.BearerTokenFormat = nullable.From(configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT)
		opts.IdentityProviders = ps
		return opts
	}
	newState := func(t *testing.T, previous *proxyState, opts *config.Options) *proxyState {
		t.Helper()
		state, err := newProxyStateFromConfig(t.Context(), previous, noop.NewTracerProvider(),
			config.New(opts), new(grpc.CachedOutboundGRPClientConn))
		require.NoError(t, err)
		return state
	}

	first := newState(t, nil, newOptions(t, providers))
	require.NotNil(t, first.idpResolver)

	// getUserInfoData discards the error from CreateSession, so an unwired
	// resolver would silently leave the dashboard without a session. Assert the
	// resolver was consulted: the failure must come from the token, not from a
	// missing provider configuration.
	t.Run("wired into the session creator", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://www.example.com", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer not.a.jwt")

		_, err = first.incomingIDPTokenSessionCreator.CreateSession(
			t.Context(), config.New(newOptions(t, providers)), nil, req)
		require.Error(t, err)
		// The resolver was consulted: the token failed issuer dispatch, rather than
		// the request being rejected for having no resolver at all.
		assert.Contains(t, err.Error(), "parse iss")
		assert.NotContains(t, err.Error(), "no identity_providers configured")
	})

	t.Run("reused across an unrelated change", func(t *testing.T) {
		opts := newOptions(t, providers)
		opts.CookieExpire = time.Hour
		assert.Same(t, first.idpResolver, newState(t, first, opts).idpResolver)
	})
}
