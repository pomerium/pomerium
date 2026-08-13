package idpsession

// Tests for cross-component contention on upstream IdP refresh tokens, run
// against a real OIDC authenticator over HTTP.
//
// The first three cover what the cluster-wide databroker singleflight provides
// when refresh tokens are one-time-use at the IdP: one presentation per liveness
// question across replicas, no clobbering of a rotated token by a stale seed,
// and so no reuse-detection revocation.
//
// The last two cover error classification and the write-ahead intent: a
// momentary outage is not a sign-out, and an attempt whose outcome was never
// observed ends the grant with a labeled record instead of failing silently, and
// without re-presenting the token.
//
// Clock note: every age the store measures is bounded by the databroker's own
// write timestamp, so a fake clock advanced to force staleness would also age
// records written moments ago. Staleness is produced with real time instead,
// from shortTokenTTL and pastDebounce below.

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	dbtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/identity"
)

// These tests run on real time. Every age the store measures comes from the
// databroker's write timestamps, so a fake clock advanced to force staleness
// would also age intents and refresh times that were written moments ago. Where
// a test needs a stored token to fall due it uses a short access-token lifetime
// and a short debounce window, and waits.
const (
	// shortTokenTTL is the access token lifetime the mock reports. It is below
	// refreshGrace, so a stored token never has margin and only the debounce
	// window can make the record usable.
	shortTokenTTL = 3 * time.Second
	// shortDebounce has to outlast a poll interval, or a caller released by
	// another replica's refresh would find the result already stale and refresh
	// again instead of adopting it.
	shortDebounce = pollMaxDelay + time.Second
	// pastDebounce is a wait that reliably leaves the debounce window.
	pastDebounce = shortDebounce + 500*time.Millisecond
)

// alwaysDue configures a store so every EnsureLive is due for a refresh with no
// waiting. Used by tests that need staleness but not adoption: the provider
// states no token lifetime, so only the debounce window could vouch for the
// stored token, and that is set to nothing.
// Zero rather than a tiny interval: a frozen fake clock reports no elapsed time
// at all, and any positive window would still count as debounced.
var alwaysDue = []Option{WithMinRefreshInterval(0)}

// TestContention_ConcurrentCrossReplicaRefresh: two Store instances (two proxy
// replicas) sharing one databroker both observe a stale record, but only one
// presents the one-time-use refresh token. The other waits on that flight and
// adopts its committed outcome, so no consumed token is replayed and neither
// caller is reported as signed out.
func TestContention_ConcurrentCrossReplicaRefresh(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users:          []*mockidp.User{{Email: "user@example.com"}},
		RotationMode:   mockidp.RotateInvalidate, // strict one-time-use
		AccessTokenTTL: shortTokenTTL,
	})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)

	// Two independent replicas: separate Store instances over one databroker.
	s1 := New(client, getAuth, WithMinRefreshInterval(shortDebounce))
	s2 := New(client, getAuth, WithMinRefreshInterval(shortDebounce))

	// Pre-warm with one successful refresh so the canonical record holds a live
	// token, the steady state before a race.
	rt0 := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s1.Register(ctx, "user-1", "idp-1", rt0))
	_, err := s1.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	prewarmed := idp.RefreshCount()

	// Let the stored token fall due, so both replicas want a refresh.
	time.Sleep(pastDebounce)

	// Hold the first grant at the IdP so that flight is still open when the second
	// replica asks the same question.
	var arrived sync.WaitGroup
	arrived.Add(1)
	release := make(chan struct{})
	var once sync.Once
	idp.SetRefreshBarrier(func(string) {
		once.Do(func() {
			arrived.Done()
			<-release
		})
	})
	t.Cleanup(func() { idp.SetRefreshBarrier(nil) })

	results := make(chan result, 2)
	go func() {
		live, err := s1.EnsureLive(ctx, "user-1", "idp-1")
		results <- result{live, err}
	}()
	arrived.Wait() // s1 is mid-presentation, holding the committed intent

	go func() {
		live, err := s2.EnsureLive(ctx, "user-1", "idp-1")
		results <- result{live, err}
	}()
	time.Sleep(200 * time.Millisecond) // let s2 observe s1's intent and wait on it
	close(release)

	r1, r2 := <-results, <-results
	for _, r := range []result{r1, r2} {
		require.NoError(t, r.err, "every replica must succeed")
		require.NotNil(t, r.live)
		assert.NotEmpty(t, r.live.Token.AccessToken)
	}
	assert.Equal(t, int64(1), idp.RefreshCount()-prewarmed,
		"one liveness question ⇒ exactly one presentation of the one-time-use token")
	assert.Equal(t, 1, idp.ValidRefreshTokenCount(),
		"nothing consumed twice, nothing stranded: only the rotated token remains")

	// The canonical record holds the rotated token, so the next refresh presents
	// the new token and succeeds.
	time.Sleep(pastDebounce)
	_, err = s2.EnsureLive(ctx, "user-1", "idp-1")
	assert.NoError(t, err, "the rotated token chain continues unbroken")
}

// TestContention_StaleRegisterDoesNotClobberRotatedToken covers Register's
// seed-if-absent behavior: a component bootstrapping from a stale copy, such as
// a browser session's OauthToken or MCPRefreshToken.UpstreamRefreshToken, cannot
// replace the freshly rotated canonical token with a consumed one.
func TestContention_StaleRegisterDoesNotClobberRotatedToken(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users:        []*mockidp.User{{Email: "user@example.com"}},
		RotationMode: mockidp.RotateInvalidate,
	})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)
	clk := &fakeClock{t: time.Now()}
	s1 := New(client, getAuth, WithNow(clk.Now))
	s2 := New(client, getAuth, WithNow(clk.Now))

	// Replica 1 refreshes, so rt1 is consumed and the canonical record holds rt2.
	rt1 := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s1.Register(ctx, "user-1", "idp-1", rt1))
	_, err := s1.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	require.Equal(t, 1, idp.ValidRefreshTokenCount())

	// Replica 2 still holds a stale copy of rt1 and re-seeds the store with it.
	// The live canonical record wins and the seed is dropped.
	require.NoError(t, s2.Register(ctx, "user-1", "idp-1", rt1))

	// Both replicas still see a working session, and the next refresh presents
	// the rotated rt2 rather than the consumed rt1.
	_, err = s2.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	clk.Advance(2 * time.Hour)
	_, err = s1.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err, "the canonical record survived the stale re-seed")
	assert.Equal(t, 1, idp.ValidRefreshTokenCount(),
		"exactly one valid token: the chain rotated, nothing was stranded")
}

// TestContention_ReuseDetectionNeverTripped runs the stale re-seed against an
// IdP with reuse detection (Auth0/Okta/Entra style), where one replay of a
// consumed token revokes the whole grant family. No consumed token is presented,
// so the family survives.
func TestContention_ReuseDetectionNeverTripped(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users:        []*mockidp.User{{Email: "user@example.com"}},
		RotationMode: mockidp.RotateReuseDetect,
	})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)
	clk := &fakeClock{t: time.Now()}
	s1 := New(client, getAuth, WithNow(clk.Now))
	s2 := New(client, getAuth, WithNow(clk.Now))

	rt1 := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s1.Register(ctx, "user-1", "idp-1", rt1))
	_, err := s1.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	require.Equal(t, 1, idp.ValidRefreshTokenCount(), "rotated token is valid")

	// A component re-seeds the consumed rt1 and refreshes. The seed is dropped and
	// the refresh presents the canonical rotated token.
	require.NoError(t, s2.Register(ctx, "user-1", "idp-1", rt1))
	clk.Advance(2 * time.Hour)
	_, err = s2.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)

	assert.Equal(t, 1, idp.ValidRefreshTokenCount(),
		"no replay ⇒ reuse detection never trips ⇒ the grant family survives")
}

// TestContention_TransientIdPOutageKeepsSession: a momentary IdP outage is an
// answered failure, so the token was not consumed. The canonical record
// survives, no projection is torn down, and the next call succeeds once the IdP
// is back. Previously this signed the user out of every browser and MCP session.
func TestContention_TransientIdPOutageKeepsSession(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users: []*mockidp.User{{Email: "user@example.com"}},
		// One-time-use, so "the token was never invalidated" is a claim the
		// provider can actually refute: under the default mode a presented token
		// stays valid regardless, and the assertion would hold either way.
		RotationMode: mockidp.RotateInvalidate,
	})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, getAuth)

	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", rt))

	// A brief IdP outage during which the token stays valid. Two failures are
	// injected because this is the provider's first token request, so its cached
	// oauth2 config has not yet learned which client-auth style the endpoint
	// accepts: x/oauth2 probes and silently retries the failure once with the
	// other style. A single 503 is absorbed by that retry. Once any token request
	// has succeeded the style is cached and one failure costs one POST, as in
	// TestContention_LostResponseDiesLabeledWithoutReplay.
	idp.FailNextRefresh(503, 2)

	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrUpstreamSessionDead, "an outage is not the user signing out")
	assert.ErrorIs(t, err, ErrRefreshUnavailable)
	assert.True(t, IsTemporary(err), "consumers must keep their sessions and retry")
	assert.True(t, idp.IsRefreshTokenValid(rt), "the refresh token was never invalidated")

	// The record survives with its token, so recovery needs only the IdP coming
	// back: no re-seeding, no re-login, no settle window. A delivered error is a
	// known failure, so the intent was cleared with it.
	live, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err, "the session comes back with the IdP")
	assert.NotEmpty(t, live.Token.AccessToken)
}

// TestContention_LostResponseDiesLabeledWithoutReplay covers what the
// write-ahead intent buys. The IdP consumes the presented token and rotates, but
// the response never reaches Pomerium, so the successor is unrecoverable. The
// grant must still not fail silently, and the consumed token must not be
// presented again, since a replay makes a reuse-detecting IdP revoke the whole
// family. The record is retired after the settle window with reason
// unknown_outcome and no further IdP contact.
func TestContention_LostResponseDiesLabeledWithoutReplay(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users:         []*mockidp.User{{Email: "user@example.com"}},
		RotationMode:  mockidp.RotateInvalidate,
		OmitExpiresIn: true,
	})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)
	// The clock tracks real time, because the ages the store measures come from
	// the databroker's write timestamps. It is moved only to cross the settle
	// window, long after the intent this test is about was written.
	clk := &fakeClock{t: time.Now()}
	s := New(client, getAuth, append(slices.Clone(alwaysDue), WithNow(clk.Now))...)

	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", rt))

	// One good refresh first, which is how the store learns this provider rotates
	// and so that re-presenting its tokens is unsafe.
	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	presented := idp.RefreshCount()

	// The grant executes at the IdP (token consumed, successor minted) but the
	// response is lost. This costs one presentation: the pre-warm above taught
	// the provider's cached oauth2 config which client-auth style this endpoint
	// accepts, so x/oauth2 no longer probes and no longer re-POSTs the failed
	// request with the other style.
	idp.DropNextRefreshResponse(1)

	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrUpstreamSessionDead, "an unobserved outcome is not a sign-out")
	assert.ErrorIs(t, err, ErrRefreshUnavailable)

	// While the attempt could still be answered, since the IdP may process a
	// request long after the client gave up, nothing may touch the token.
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrRefreshUnavailable, "the intent holds every caller off the token")
	assert.Equal(t, presented+1, idp.RefreshCount(), "no caller re-presents while the intent stands")

	// Once nothing can still be in flight the record is resolved without
	// contacting the IdP, giving a labeled failure rather than a silent one.
	clk.Advance(settleDelay + time.Second)
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrUpstreamSessionDead)
	assert.Equal(t, deadReasonUnknownOutcome, DeadReason(err))
	assert.Equal(t, presented+1, idp.RefreshCount(),
		"resolution is a local decision: the consumed token is never replayed")
	assert.Equal(t, 1, idp.ValidRefreshTokenCount(),
		"the orphaned successor is stranded, but the family was never revoked")

	// Death is absolute: a component still holding the consumed token cannot
	// resurrect the record with it, and neither can any other copy of the same
	// grant. Only a fresh login does.
	assert.ErrorIs(t, s.Register(ctx, "user-1", "idp-1", rt), ErrUpstreamSessionDead,
		"a stale copy must not resurrect a dead session")
	assert.ErrorIs(t, s.Register(ctx, "user-1", "idp-1", "some-other-copy"), ErrUpstreamSessionDead)

	fresh := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s.Supersede(ctx, "user-1", "idp-1", fresh, "id-token-from-login"))
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	assert.NoError(t, err, "signing in again is what brings the user back")
}

// TestFamilyCostIsOnePresentationPerWindow measures what the shared record buys
// against what it replaced. Many consumers of one user — several replicas, each
// asking repeatedly — cost one presentation of the upstream refresh token per
// debounce window between them, where before this package each consumer
// presented its own copy on its own schedule.
//
// It also pins the shape of the family: one token deep. A design that leaked a
// rotation would leave several tokens the provider still accepts.
func TestFamilyCostIsOnePresentationPerWindow(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users:        []*mockidp.User{{Email: "user@example.com"}},
		RotationMode: mockidp.RotateReuseDetect,
		// Below refreshGrace, so a stored token never has margin and the
		// debounce window is the only thing that can make the record usable.
		// With a long-lived token the first refresh would cover the whole test
		// and the count below would pass without measuring anything.
		AccessTokenTTL: shortTokenTTL,
	})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)

	// Three replicas sharing one databroker, as a deployment has.
	const replicas, callsPerWindow, windows = 3, 20, 3
	stores := make([]*Store, replicas)
	for i := range stores {
		stores[i] = New(client, getAuth, WithMinRefreshInterval(shortDebounce))
	}

	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, stores[0].Register(ctx, "user-1", "idp-1", rt))

	before := idp.RefreshCount()
	// Counted so the error-branch assertion above cannot pass vacuously: a run
	// where every caller was told to retry would satisfy it while proving
	// nothing about what consumers get.
	var served atomic.Int64
	for w := range windows {
		if w > 0 {
			// Leave the window, so the next round is a fresh liveness question
			// rather than a read of what the last one committed.
			time.Sleep(pastDebounce)
		}
		var wg sync.WaitGroup
		for range callsPerWindow {
			for _, s := range stores {
				wg.Go(func() {
					live, err := s.EnsureLive(ctx, "user-1", "idp-1")
					// A caller suppressed by the one doing the work may be told
					// to retry, but never that the grant is over.
					if err != nil {
						assert.True(t, IsTemporary(err), "unexpected terminal error: %v", err)
						return
					}
					require.NotNil(t, live)
					assert.NotEmpty(t, live.Token.AccessToken)
					served.Add(1)
				})
			}
		}
		wg.Wait()
	}

	grants := replicas * callsPerWindow * windows
	presentations := idp.RefreshCount() - before
	t.Logf("%d liveness questions across %d replicas cost %d presentations", grants, replicas, presentations)

	assert.Positive(t, served.Load(), "the callers must actually be served tokens, not only told to retry")
	assert.Positive(t, presentations, "the questions must actually reach the provider")
	assert.GreaterOrEqual(t, presentations, int64(2),
		"the windows must actually be crossed, or this measures nothing")
	assert.LessOrEqual(t, presentations, int64(windows),
		"at most one presentation per debounce window, however many consumers ask")
	assert.Less(t, presentations, int64(grants),
		"the whole point is that consumers do not each present their own copy")
	assert.Equal(t, 1, idp.ValidRefreshTokenCount(),
		"the family stays one token deep: no rotation was leaked")
}

// TestAtMostOncePerToken is the concurrency pin for the first invariant. Many
// callers across replicas race on one record against a provider that revokes the
// whole family if a consumed token is presented again, and no token value is
// ever presented twice.
//
// Counting presentations is not enough on its own: two calls presenting the same
// token look the same as two presenting different ones, so the authenticator
// records every value it is handed.
func TestAtMostOncePerToken(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users:         []*mockidp.User{{Email: "user@example.com"}},
		RotationMode:  mockidp.RotateReuseDetect,
		OmitExpiresIn: true, // every call is due, so callers keep racing
	})
	realGet := realAuthenticator(t, idp)

	// Wrap the real authenticator so every presented refresh token is recorded.
	var mu sync.Mutex
	presented := map[string]int{}
	getAuth := func(ctx context.Context, idpID string) (identity.Authenticator, error) {
		auth, err := realGet(ctx, idpID)
		if err != nil {
			return nil, err
		}
		return recordingAuthenticator{Authenticator: auth, mu: &mu, presented: presented}, nil
	}

	client := dbtestutil.NewTestDatabroker(t)
	const replicas, callers = 3, 15
	stores := make([]*Store, replicas)
	for i := range stores {
		stores[i] = New(client, getAuth, alwaysDue...)
	}

	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, stores[0].Register(ctx, "user-1", "idp-1", rt))

	var wg sync.WaitGroup
	for range callers {
		for _, s := range stores {
			wg.Go(func() {
				if _, err := s.EnsureLive(ctx, "user-1", "idp-1"); err != nil {
					assert.True(t, IsTemporary(err), "unexpected terminal error: %v", err)
				}
			})
		}
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, presented, "the race must actually reach the provider")
	for token, n := range presented {
		assert.Equal(t, 1, n, "refresh token %q was presented %d times", token, n)
	}
	assert.Equal(t, 1, idp.ValidRefreshTokenCount(),
		"reuse detection never fired: the family survived")
}

// recordingAuthenticator counts how often each refresh token value is presented.
type recordingAuthenticator struct {
	identity.Authenticator
	mu        *sync.Mutex
	presented map[string]int
}

func (r recordingAuthenticator) Refresh(ctx context.Context, t *oauth2.Token, v identity.State) (*oauth2.Token, error) {
	r.mu.Lock()
	r.presented[t.RefreshToken]++
	r.mu.Unlock()
	return r.Authenticator.Refresh(ctx, t, v)
}

// TestReuseDetectionFiresOnAReplay validates the detector the other tests in
// this file rely on. Several of them assert that reuse detection never fired,
// which means nothing unless presenting a consumed token actually revokes the
// family. This one does that deliberately.
func TestReuseDetectionFiresOnAReplay(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users:        []*mockidp.User{{Email: "user@example.com"}},
		RotationMode: mockidp.RotateReuseDetect,
	})
	getAuth := realAuthenticator(t, idp)
	auth, err := getAuth(ctx, "idp-1")
	require.NoError(t, err)

	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	require.True(t, idp.IsRefreshTokenValid(rt))

	// One presentation consumes it and mints a successor.
	tok, err := auth.Refresh(ctx, &oauth2.Token{RefreshToken: rt}, newClaimsCapture())
	require.NoError(t, err)
	require.NotEmpty(t, tok.RefreshToken)
	require.NotEqual(t, rt, tok.RefreshToken, "this provider rotates")
	require.False(t, idp.IsRefreshTokenValid(rt), "the presented token is consumed")
	require.Equal(t, 1, idp.ValidRefreshTokenCount(), "only the successor remains")

	// Presenting the consumed one again is a replay, and takes the whole family
	// with it. This is the outcome every "never presented twice" assertion in
	// this package exists to avoid.
	_, err = auth.Refresh(ctx, &oauth2.Token{RefreshToken: rt}, newClaimsCapture())
	require.Error(t, err, "a replayed token must be refused")
	assert.Equal(t, 0, idp.ValidRefreshTokenCount(),
		"reuse detection revokes the successor too: the family is gone")
	assert.False(t, idp.IsRefreshTokenValid(tok.RefreshToken))
}

// TestAttempt_SuccessDiscardedWhenTheRecordDiedMeanwhile pins the guard that
// enforces death being absolute. An attempt that is at the IdP when the record
// is retired comes back holding a valid token and a successful result; writing
// it would resurrect the tombstone. The ownership check on the attempt id is
// what discards it.
func TestAttempt_SuccessDiscardedWhenTheRecordDiedMeanwhile(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now, rotateTo: "rt-2", block: make(chan struct{})}
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, newAuthGetter(auth), WithNow(clk.Now))

	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.EnsureLive(ctx, "user-1", "idp-1")
	}()

	// Hold the attempt at the IdP, then retire the record underneath it the way
	// a sign-out or a settle-window resolution on another replica would.
	require.Eventually(t, func() bool { return auth.callCount() == 1 }, 10*time.Second, 10*time.Millisecond)
	require.NoError(t, s.Revoke(ctx, "user-1", "idp-1"))
	close(auth.block)
	<-done

	// The attempt's success is thrown away: the record it describes is no longer
	// the canonical one.
	require.Eventually(t, func() bool {
		rec, err := s.get(ctx, RecordID("user-1", "idp-1"))
		return err == nil && isDead(rec)
	}, 10*time.Second, 20*time.Millisecond, "the tombstone must survive the attempt's success")

	rec, err := s.get(ctx, RecordID("user-1", "idp-1"))
	require.NoError(t, err)
	assert.Equal(t, deadReasonPomeriumSignout, rec.GetDeadReason())
	assert.Empty(t, rec.GetUpstreamRefreshToken(), "a tombstone holds no token, rotated or not")
	assert.Empty(t, rec.GetRefreshAttemptId())

	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrUpstreamSessionDead)
}
