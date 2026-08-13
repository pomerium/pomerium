package manager

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/identity/idpsession"
	"github.com/pomerium/pomerium/internal/testutil"
	dbtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
)

// newInMemoryDatabroker returns a client backed by a real in-memory databroker,
// so the unified-refresh tests can assert on actually-stored records.

// countingAuth counts Refresh calls so the unification tests can assert exactly
// how many times the IdP was hit for a given user.
type countingAuth struct {
	identity.Authenticator
	mu             sync.Mutex
	calls          int
	lastOldRefresh string
	err            error
	now            func() time.Time
	lifetime       time.Duration
}

func (a *countingAuth) Refresh(_ context.Context, t *oauth2.Token, _ identity.State) (*oauth2.Token, error) {
	a.mu.Lock()
	a.calls++
	a.lastOldRefresh = t.RefreshToken
	err := a.err
	a.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &oauth2.Token{AccessToken: "fresh-access-token", TokenType: "Bearer", Expiry: a.now().Add(a.lifetime)}, nil
}

func (a *countingAuth) UpdateUserInfo(context.Context, *oauth2.Token, any) error { return nil }

func (a *countingAuth) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

func newUnifiedManager(t *testing.T, client databroker_grpc.DataBrokerServiceClient, auth identity.Authenticator, now func() time.Time) *Manager {
	t.Helper()
	getAuth := func(context.Context, string) (identity.Authenticator, error) { return auth, nil }
	store := idpsession.New(client, getAuth, idpsession.WithNow(now))
	return New(
		WithDataBrokerClient(client),
		WithGetAuthenticator(getAuth),
		WithIDPSessionStore(store),
		WithNow(now),
	)
}

func liveSession(id, userID string, now time.Time) *session.Session {
	return &session.Session{
		Id:        id,
		UserId:    userID,
		IdpId:     "idp-1",
		IssuedAt:  timestamppb.New(now),
		ExpiresAt: timestamppb.New(now.Add(24 * time.Hour)),
		OauthToken: &session.OAuthToken{
			AccessToken:  "stale-access-token",
			RefreshToken: "rt-session",
		},
	}
}

func TestUnifiedRefresh_RoutesThroughStore(t *testing.T) {
	ctx := testutil.GetContext(t, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	client := dbtestutil.NewTestDatabroker(t)
	auth := &countingAuth{now: func() time.Time { return now }, lifetime: time.Hour}
	mgr := newUnifiedManager(t, client, auth, func() time.Time { return now })

	// A canonical upstream session already exists (seeded at login/approval).
	store := idpsession.New(client, func(context.Context, string) (identity.Authenticator, error) { return auth, nil }, idpsession.WithNow(func() time.Time { return now }))
	require.NoError(t, store.Register(ctx, "user-1", "idp-1", "rt-canonical"))

	sess := liveSession("session-1", "user-1", now)
	_, err := session.Put(ctx, client, sess)
	require.NoError(t, err)
	mgr.onUpdateSession(ctx, sess)

	mgr.refreshSession(ctx, "session-1")

	assert.Equal(t, 1, auth.callCount(), "manager must refresh via the store exactly once")
	assert.Equal(t, "rt-canonical", auth.lastOldRefresh, "store owns the refresh token, not the session")

	got, err := session.Get(ctx, client, "session-1")
	require.NoError(t, err)
	assert.Equal(t, "fresh-access-token", got.GetOauthToken().GetAccessToken(), "session must be repopulated from the store")
}

func TestUnifiedRefresh_NoAmplificationAcrossSessions(t *testing.T) {
	ctx := testutil.GetContext(t, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	client := dbtestutil.NewTestDatabroker(t)
	auth := &countingAuth{now: func() time.Time { return now }, lifetime: time.Hour}
	mgr := newUnifiedManager(t, client, auth, func() time.Time { return now })

	store := idpsession.New(client, func(context.Context, string) (identity.Authenticator, error) { return auth, nil }, idpsession.WithNow(func() time.Time { return now }))
	require.NoError(t, store.Register(ctx, "user-1", "idp-1", "rt-canonical"))

	// Two browser sessions for the SAME user.
	for _, id := range []string{"session-1", "session-2"} {
		s := liveSession(id, "user-1", now)
		_, err := session.Put(ctx, client, s)
		require.NoError(t, err)
		mgr.onUpdateSession(ctx, s)
	}

	mgr.refreshSession(ctx, "session-1")
	mgr.refreshSession(ctx, "session-2")

	assert.Equal(t, 1, auth.callCount(), "refreshing N sessions of one user must cause only ONE IdP call")
}

func TestUnifiedRefresh_DeadUpstreamDeletesSession(t *testing.T) {
	ctx := testutil.GetContext(t, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	client := dbtestutil.NewTestDatabroker(t)
	auth := &countingAuth{
		now: func() time.Time { return now }, lifetime: time.Hour,
		// RFC 6749 §5.2: only the IdP's own refusal of the grant is permanent.
		err: &oauth2.RetrieveError{
			Response:  &http.Response{StatusCode: http.StatusBadRequest},
			ErrorCode: "invalid_grant",
		},
	}
	mgr := newUnifiedManager(t, client, auth, func() time.Time { return now })

	store := idpsession.New(client, func(context.Context, string) (identity.Authenticator, error) { return auth, nil }, idpsession.WithNow(func() time.Time { return now }))
	require.NoError(t, store.Register(ctx, "user-1", "idp-1", "rt-canonical"))

	sess := liveSession("session-1", "user-1", now)
	_, err := session.Put(ctx, client, sess)
	require.NoError(t, err)
	mgr.onUpdateSession(ctx, sess)

	mgr.refreshSession(ctx, "session-1")

	_, err = session.Get(ctx, client, "session-1")
	assert.True(t, databroker_grpc.IsNotFound(err), "a permanently-dead upstream session must delete the browser session")
}

// TestUnifiedRefresh_TransientUpstreamKeepsSession: an upstream failure whose
// outcome is not a refusal must never delete a session. The store reports it as
// temporary and the manager keeps the session for the next cycle.
func TestUnifiedRefresh_TransientUpstreamKeepsSession(t *testing.T) {
	ctx := testutil.GetContext(t, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	client := dbtestutil.NewTestDatabroker(t)
	auth := &countingAuth{
		now: func() time.Time { return now }, lifetime: time.Hour,
		err: &oauth2.RetrieveError{Response: &http.Response{StatusCode: http.StatusServiceUnavailable}},
	}
	mgr := newUnifiedManager(t, client, auth, func() time.Time { return now })

	store := idpsession.New(client, func(context.Context, string) (identity.Authenticator, error) { return auth, nil }, idpsession.WithNow(func() time.Time { return now }))
	require.NoError(t, store.Register(ctx, "user-1", "idp-1", "rt-canonical"))

	sess := liveSession("session-1", "user-1", now)
	_, err := session.Put(ctx, client, sess)
	require.NoError(t, err)
	mgr.onUpdateSession(ctx, sess)

	mgr.refreshSession(ctx, "session-1")

	got, err := session.Get(ctx, client, "session-1")
	require.NoError(t, err, "a momentary upstream failure must not sign the user out")
	assert.Equal(t, "stale-access-token", got.GetOauthToken().GetAccessToken())

	_, err = store.EnsureLive(ctx, "user-1", "idp-1")
	assert.True(t, idpsession.IsTemporary(err), "the manager's own predicate must read it as temporary")
}

func TestUnifiedRefresh_BootstrapsCanonicalFromSession(t *testing.T) {
	ctx := testutil.GetContext(t, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	client := dbtestutil.NewTestDatabroker(t)
	auth := &countingAuth{now: func() time.Time { return now }, lifetime: time.Hour}
	mgr := newUnifiedManager(t, client, auth, func() time.Time { return now })

	// No canonical record exists (pre-migration session). The manager must seed
	// it from the session's own refresh token, then refresh through the store.
	sess := liveSession("session-1", "user-1", now)
	sess.OauthToken.RefreshToken = "rt-bootstrap"
	_, err := session.Put(ctx, client, sess)
	require.NoError(t, err)
	mgr.onUpdateSession(ctx, sess)

	mgr.refreshSession(ctx, "session-1")

	assert.Equal(t, 1, auth.callCount())
	assert.Equal(t, "rt-bootstrap", auth.lastOldRefresh, "bootstrap must seed the canonical record from the session token")
	got, err := session.Get(ctx, client, "session-1")
	require.NoError(t, err)
	assert.Equal(t, "fresh-access-token", got.GetOauthToken().GetAccessToken())
}

// TestUnifiedRefresh_DatabrokerFailureKeepsSession: the store reports databroker
// failures as typed gRPC status errors. Only a dead or missing upstream session
// may delete a session, so an infrastructure failure has to leave it alone —
// otherwise a databroker blip signs out every user whose refresh happened to
// land during it.
func TestUnifiedRefresh_DatabrokerFailureKeepsSession(t *testing.T) {
	ctx := testutil.GetContext(t, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	client := dbtestutil.NewTestDatabroker(t)
	auth := &countingAuth{now: func() time.Time { return now }, lifetime: time.Hour}

	sess := liveSession("session-1", "user-1", now)
	_, err := session.Put(ctx, client, sess)
	require.NoError(t, err)

	for _, code := range []codes.Code{
		codes.Unavailable, codes.Aborted, codes.DeadlineExceeded, codes.Internal, codes.FailedPrecondition,
	} {
		t.Run(code.String(), func(t *testing.T) {
			broken := dbtestutil.FailingDatabroker(client, status.Error(code, "databroker is down"))
			store := idpsession.New(broken,
				func(context.Context, string) (identity.Authenticator, error) { return auth, nil },
				idpsession.WithNow(func() time.Time { return now }))

			// The manager reads and writes sessions through the working client;
			// only the canonical upstream record is unreachable.
			mgr := New(
				WithDataBrokerClient(client),
				WithGetAuthenticator(func(context.Context, string) (identity.Authenticator, error) { return auth, nil }),
				WithIDPSessionStore(store),
				WithNow(func() time.Time { return now }),
			)
			mgr.onUpdateSession(ctx, sess)
			mgr.refreshSession(ctx, "session-1")

			got, err := session.Get(ctx, client, "session-1")
			require.NoError(t, err, "an unreachable databroker must not sign the user out")
			assert.Equal(t, "stale-access-token", got.GetOauthToken().GetAccessToken())

			_, err = store.EnsureLive(ctx, "user-1", "idp-1")
			assert.True(t, idpsession.IsTemporary(err), "the store reports it as retryable, got %v", err)
			assert.NotErrorIs(t, err, idpsession.ErrUpstreamSessionDead,
				"an unreachable databroker is not a statement about the grant")
		})
	}
}

// signedIDToken builds a parseable ID token. session.SetRawIDToken parses what
// it is given and stores nothing when parsing fails, so a plain string would
// make these tests pass or fail for the wrong reason.
func signedIDToken(t *testing.T, subject string, expiry time.Time) string {
	t.Helper()
	key := []byte("0123456789abcdef0123456789abcdef")
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: key}, nil)
	require.NoError(t, err)
	raw, err := jwt.Signed(sig).Claims(jwt.Claims{
		Issuer:   "https://idp.example.com",
		Subject:  subject,
		Expiry:   jwt.NewNumericDate(expiry),
		IssuedAt: jwt.NewNumericDate(expiry.Add(-time.Hour)),
	}).CompactSerialize()
	require.NoError(t, err)
	return raw
}

// idTokenAuth returns a token whose access token outlives its ID token, the
// shape Auth0 and Okta produce, and issues a distinct raw ID token per refresh
// so a test can see whether the session's advanced.
type idTokenAuth struct {
	identity.Authenticator
	mu             sync.Mutex
	calls          int
	issued         []string
	now            func() time.Time
	accessLifetime time.Duration
	newIDToken     func(n int) string
}

func (a *idTokenAuth) Refresh(_ context.Context, _ *oauth2.Token, v identity.State) (*oauth2.Token, error) {
	a.mu.Lock()
	a.calls++
	n := a.calls
	raw := a.newIDToken(n)
	a.issued = append(a.issued, raw)
	a.mu.Unlock()
	if v != nil {
		v.SetRawIDToken(raw)
	}
	return &oauth2.Token{
		AccessToken: "fresh-access-token",
		TokenType:   "Bearer",
		Expiry:      a.now().Add(a.accessLifetime),
	}, nil
}

func (a *idTokenAuth) UpdateUserInfo(context.Context, *oauth2.Token, any) error { return nil }

func (a *idTokenAuth) callCount() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.calls
}

// TestUnifiedRefresh_ScheduledRefreshAdvancesTheIDToken: a scheduled refresh
// means something about the session hit its expiry, so it has to present rather
// than be served a stored access token that merely has not expired.
//
// With refresh_session_at_id_token_expiration set and a provider whose ID token
// expires long before its access token, being served from the record would leave
// the session's ID token stale, the scheduler would keep computing a past-due
// time from it, and the manager would spin at its cool-off interval for the life
// of the session while forwarding an expired ID token upstream.
func TestUnifiedRefresh_ScheduledRefreshAdvancesTheIDToken(t *testing.T) {
	ctx := testutil.GetContext(t, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	client := dbtestutil.NewTestDatabroker(t)
	auth := &idTokenAuth{
		now:            func() time.Time { return now },
		accessLifetime: 24 * time.Hour,
		// The ID token expires long before the access token, the Auth0 shape.
		newIDToken: func(n int) string {
			return signedIDToken(t, fmt.Sprintf("user-1-refresh-%d", n), now.Add(10*time.Hour))
		},
	}
	mgr := newUnifiedManager(t, client, auth, func() time.Time { return now })

	sess := liveSession("session-1", "user-1", now)
	_, err := session.Put(ctx, client, sess)
	require.NoError(t, err)
	mgr.onUpdateSession(ctx, sess)

	// The first scheduled refresh presents and the session's ID token advances.
	mgr.refreshSession(ctx, "session-1")
	require.Equal(t, 1, auth.callCount(), "a scheduled refresh presents upstream")
	got, err := session.Get(ctx, client, "session-1")
	require.NoError(t, err)
	require.Equal(t, auth.issued[0], got.GetIdToken().GetRaw(), "the session's id token advanced")

	// Everything after this is inside the debounce window, which is what collapses
	// a herd of replicas. It must not turn into a spin: the store answers from
	// the record and no further presentation happens.
	for range 20 {
		mgr.refreshSession(ctx, "session-1")
	}
	assert.Equal(t, 1, auth.callCount(),
		"repeated ticks inside the debounce window must not each present upstream")

	// Past the window a scheduled refresh presents again and advances the ID
	// token once more, rather than serving the stale one forever.
	later := now.Add(idpsession.DefaultMinRefreshInterval + time.Minute)
	mgr2 := newUnifiedManager(t, client, auth, func() time.Time { return later })
	mgr2.onUpdateSession(ctx, got)
	mgr2.refreshSession(ctx, "session-1")
	assert.Equal(t, 2, auth.callCount(), "a later scheduled refresh presents again")
	got, err = session.Get(ctx, client, "session-1")
	require.NoError(t, err)
	assert.Equal(t, auth.issued[1], got.GetIdToken().GetRaw())
}

// TestUnifiedRefresh_ProviderOmittingIDTokenKeepsTheLoginOne: most providers do
// not return id_token on refresh. Blanking the session's on every refresh would
// break the route id-token headers, sign-out's id_token_hint, and refreshing at
// ID-token expiry.
func TestUnifiedRefresh_ProviderOmittingIDTokenKeepsTheLoginOne(t *testing.T) {
	ctx := testutil.GetContext(t, time.Minute)
	now := time.Unix(1_700_000_000, 0)
	client := dbtestutil.NewTestDatabroker(t)
	// countingAuth never touches the identity.State, which is exactly a provider
	// that omits id_token on refresh.
	auth := &countingAuth{now: func() time.Time { return now }, lifetime: time.Hour}
	mgr := newUnifiedManager(t, client, auth, func() time.Time { return now })

	store := idpsession.New(client,
		func(context.Context, string) (identity.Authenticator, error) { return auth, nil },
		idpsession.WithNow(func() time.Time { return now }))
	require.NoError(t, store.Register(ctx, "user-1", "idp-1", "rt-canonical"))

	loginIDToken := signedIDToken(t, "user-1", now.Add(10*time.Hour))
	sess := liveSession("session-1", "user-1", now)
	sess.SetRawIDToken(loginIDToken)
	require.NotNil(t, sess.GetIdToken(), "the fixture's id token must parse")
	_, err := session.Put(ctx, client, sess)
	require.NoError(t, err)
	mgr.onUpdateSession(ctx, sess)

	mgr.refreshSession(ctx, "session-1")

	got, err := session.Get(ctx, client, "session-1")
	require.NoError(t, err)
	require.Equal(t, 1, auth.calls, "the refresh happened")
	assert.Equal(t, loginIDToken, got.GetIdToken().GetRaw(),
		"a provider that says nothing about id_token must not blank the session's")
}
