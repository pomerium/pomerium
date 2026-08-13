package idpsession

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	dbtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
)

// realAuthenticator builds an OIDC authenticator with real discovery and JWKS
// verification pointed at a mock IdP, so the store's refresh path runs over HTTP
// against an actual /oidc/token endpoint.
func realAuthenticator(t *testing.T, idp *mockidp.IDP) AuthenticatorGetter {
	t.Helper()
	idpURL := idp.Start(t)
	ctx := testutil.GetContext(t, time.Minute)
	auth, err := oidc.New(ctx, &oauth.Options{
		ProviderURL:  idpURL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURL:  &url.URL{Scheme: "https", Host: "pomerium.example.com", Path: "/oauth2/callback"},
	})
	require.NoError(t, err)
	return func(context.Context, string) (identity.Authenticator, error) { return auth, nil }
}

func TestStore_RealOIDC_RefreshOnceAcrossManyCalls(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{Users: []*mockidp.User{{Email: "user@example.com"}}})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, getAuth)

	// Simulate a completed login: the user has a valid upstream refresh token.
	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", rt))

	live, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	require.NotNil(t, live)
	assert.NotEmpty(t, live.Token.AccessToken, "must obtain a real access token from the IdP")
	assert.Equal(t, int64(1), idp.RefreshCount())

	// Many consumers (browser sessions, MCP clients) poll for liveness. The token
	// is still fresh, so the IdP is not called again.
	for range 20 {
		_, err := s.EnsureLive(ctx, "user-1", "idp-1")
		require.NoError(t, err)
	}
	assert.Equal(t, int64(1), idp.RefreshCount(), "N consumers must not amplify IdP refreshes")
}

// TestStore_RealOIDC_NoExpiresInStaysUsable covers providers that omit
// expires_in. The stored token has no known expiry, so the record is trusted for
// the debounce window instead of being read as already expired. Otherwise the
// record would never be usable and every caller but the one that refreshed would
// get a transient error.
func TestStore_RealOIDC_NoExpiresInStaysUsable(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users:         []*mockidp.User{{Email: "user@example.com"}},
		OmitExpiresIn: true,
	})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)
	clk := &fakeClock{t: time.Now()}
	s := New(client, getAuth, WithNow(clk.Now))

	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", rt))

	live, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	require.NotNil(t, live)
	require.True(t, live.Token.Expiry.IsZero(), "the provider stated no expiry")
	require.Equal(t, int64(1), idp.RefreshCount())

	// Every other consumer inside the debounce window is served from the record.
	for range 10 {
		_, err := s.EnsureLive(ctx, "user-1", "idp-1")
		require.NoError(t, err, "an unstated expiry must not black out other callers")
	}
	assert.Equal(t, int64(1), idp.RefreshCount())

	// Past the window the token is refreshed again, so liveness is still checked.
	clk.Advance(DefaultMinRefreshInterval + time.Second)
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	assert.Equal(t, int64(2), idp.RefreshCount(),
		"one idp call per debounce window, not one per caller")
}

func TestStore_RealOIDC_RevokedUpstreamIsDead(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{Users: []*mockidp.User{{Email: "user@example.com"}}})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, getAuth)

	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", rt))

	// The user signs out at the IdP: every refresh token is now invalid.
	idp.RevokeAllRefreshTokens()

	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrUpstreamSessionDead)
	assert.Equal(t, deadReasonSeedInvalid, DeadReason(err),
		"a seeded token that never validated died as a stale seed, not as a sign-out")

	// Death is stored as state, so every later consumer is told the session is
	// over rather than "no session", which would make them all re-seed.
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrUpstreamSessionDead)
	assert.Equal(t, int64(2), idp.RefreshCount(),
		"a dead record is answered from state; nothing is presented to the IdP again")
	// Two POSTs for one logical refresh: no token request has ever succeeded for
	// this provider, so its cached oauth2 config has no client-auth style yet and
	// x/oauth2 retries the refusal once with the other style. The second
	// EnsureLive costs nothing, which is what this test checks.
}

// TestStore_RealOIDC_WarmConfigCostsOnePOST pins what caching the provider's
// oauth2 config buys. An oauth2.Config remembers which client-auth style the
// token endpoint accepted; rebuilt per call, x/oauth2 re-probes on every token
// request and silently re-POSTs a failed one with the other style, which
// presents a one-time-use refresh token twice on a single failed refresh.
func TestStore_RealOIDC_WarmConfigCostsOnePOST(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users:         []*mockidp.User{{Email: "user@example.com"}},
		RotationMode:  mockidp.RotateInvalidate,
		OmitExpiresIn: true,
	})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, getAuth, alwaysDue...)

	// Warm the client-auth style the way a deployment does, with the login-time
	// code exchange.
	auth, err := getAuth(ctx, "idp-1")
	require.NoError(t, err)
	_, err = auth.Authenticate(ctx, idp.AuthCode("user@example.com", "test-client"), newClaimsCapture())
	require.NoError(t, err)
	idp.RevokeAllRefreshTokens()

	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", rt))

	before := idp.RefreshCount()
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), idp.RefreshCount()-before,
		"a warm config presents the token once per logical refresh")

	// A failed refresh costs one POST too, which is the case that matters: a
	// second presentation of a one-time-use token is what revokes the family.
	idp.RevokeAllRefreshTokens()
	before = idp.RefreshCount()
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.Error(t, err)
	assert.Equal(t, int64(1), idp.RefreshCount()-before,
		"a refusal is not silently retried with the other client-auth style")
}
