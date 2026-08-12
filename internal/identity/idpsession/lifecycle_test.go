package idpsession

// Tests for the record's lifecycle: death stored as state, revival by a fresh
// grant, and the effect of the write-ahead intent on callers not holding it.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/timestamppb"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	dbtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// result is what a concurrent EnsureLive goroutine reports back.
type result struct {
	live *Live
	err  error
}

// putRecord writes a canonical record directly, so a test can start from a state
// that only a crashed or concurrent writer would leave behind.
func putRecord(ctx context.Context, t *testing.T, client databroker_grpc.DataBrokerServiceClient, rec *oauth21proto.UpstreamIdPSession) {
	t.Helper()
	_, err := databroker_grpc.Put(ctx, client, rec)
	require.NoError(t, err)
}

// deleteRecord soft-deletes the canonical record the way a pre-upgrade replica's
// Revoke, or a storage GC, would, so a test can make the record vanish while an
// attempt is already at the IdP.
func deleteRecord(t *testing.T, ctx context.Context, client databroker_grpc.DataBrokerServiceClient, id string) {
	t.Helper()
	rec := newRecord(&oauth21proto.UpstreamIdPSession{Id: id})
	rec.DeletedAt = timestamppb.Now()
	_, err := client.Put(ctx, &databroker_grpc.PutRequest{Records: []*databroker_grpc.Record{rec}})
	require.NoError(t, err)
}

// TestIntent_CommittedIntentOutlivesTheCaller: committing the intent obliges the
// attempt to commit an outcome. If the caller's context is cancelled
// mid-presentation (a pod restart, an MCP client hanging up, a lost manager
// lease) and nothing is written, the record keeps a dangling intent that
// resolves to a DEAD record one settle window later. A disconnecting client must
// not sign the user out everywhere.
func TestIntent_CommittedIntentOutlivesTheCaller(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now, rotateTo: "rt-2", block: make(chan struct{})}
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, newAuthGetter(auth), WithNow(clk.Now))
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	callerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = s.EnsureLive(callerCtx, "user-1", "idp-1")
	}()

	require.Eventually(t, func() bool { return auth.callCount() == 1 }, 5*time.Second, 10*time.Millisecond,
		"the token is at the IdP with our intent committed")
	cancel() // the caller goes away mid-presentation
	close(auth.block)
	<-done

	// The caller stopped waiting, but the attempt owes the cluster an outcome and
	// runs to completion on its own context.
	require.Eventually(t, func() bool {
		rec, err := s.get(ctx, RecordID("user-1", "idp-1"))
		return err == nil && rec.GetRefreshAttemptId() == "" && rec.GetGeneration() == 1
	}, 10*time.Second, 20*time.Millisecond, "the outcome is committed, not left dangling")

	rec, err := s.get(ctx, RecordID("user-1", "idp-1"))
	require.NoError(t, err)
	assert.Equal(t, "rt-2", rec.GetUpstreamRefreshToken(),
		"the rotated token is not lost with the caller that asked for it")
}

// TestAttempt_SuccessfulRotationSurvivesAVanishedRecord: the record disappears
// during the IdP call, but the refresh succeeded, so the attempt holds the newest
// token in the family. Reporting "no upstream session" would make every consumer
// Register its own, by now consumed, copy. The rotation is written back instead.
func TestAttempt_SuccessfulRotationSurvivesAVanishedRecord(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now, rotateTo: "rt-2", block: make(chan struct{})}
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, newAuthGetter(auth), WithNow(clk.Now))
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	results := make(chan result, 1)
	go func() {
		live, err := s.EnsureLive(ctx, "user-1", "idp-1")
		results <- result{live, err}
	}()

	require.Eventually(t, func() bool { return auth.callCount() == 1 }, 5*time.Second, 10*time.Millisecond)
	deleteRecord(t, ctx, client, RecordID("user-1", "idp-1"))
	close(auth.block)

	r := <-results
	require.NoError(t, r.err, "a successful rotation is never reported as a missing session")
	require.NotNil(t, r.live)
	assert.Equal(t, "rt-2", r.live.Token.RefreshToken)

	rec, err := s.get(ctx, RecordID("user-1", "idp-1"))
	require.NoError(t, err, "the record is rewritten, because we hold the only usable token")
	assert.Equal(t, oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_LIVE, rec.GetState())
	assert.Equal(t, "rt-2", rec.GetUpstreamRefreshToken())
	assert.Equal(t, uint64(1), rec.GetGeneration())
	assert.Empty(t, rec.GetRefreshAttemptId())
}

func TestRevoke_IsAbsolute(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)

	idp := mockidp.New(mockidp.Config{Users: []*mockidp.User{{Email: "user@example.com"}}})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, getAuth)

	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", rt))
	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)

	// Signing out of Pomerium ends the shared upstream session for every
	// projection at once.
	require.NoError(t, s.Revoke(ctx, "user-1", "idp-1"))

	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrUpstreamSessionDead)
	assert.Equal(t, deadReasonPomeriumSignout, DeadReason(err))

	// Every consumer still holds a copy of the old token. None of them may bring
	// the session back, or signing out would last only until the next poll.
	err = s.Register(ctx, "user-1", "idp-1", rt)
	assert.ErrorIs(t, err, ErrUpstreamSessionDead)

	rec, err := s.get(ctx, RecordID("user-1", "idp-1"))
	require.NoError(t, err)
	assert.Empty(t, rec.GetUpstreamRefreshToken(), "a tombstone must not be a place to find a token")
	assert.Empty(t, rec.GetUpstreamAccessToken())

	// A signout is the one death no held token overrides, so even a genuinely
	// fresh token does not revive it.
	fresh := idp.IssueRefreshToken("user@example.com", "test-client")
	assert.ErrorIs(t, s.Register(ctx, "user-1", "idp-1", fresh), ErrUpstreamSessionDead,
		"nothing revives a record the user signed out of")
}

// TestRegister_NeverDowngradesALiveRecord: an offered copy can be older than the
// token the store has since rotated to, so a live record is left alone. Taking
// the offer would install a stale token and lose the rotation.
func TestRegister_NeverDowngradesALiveRecord(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now, rotateTo: "rt-rotated"}
	s := newTestStore(t, auth, clk)

	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-old"))
	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	require.Equal(t, "rt-old", auth.lastPresented())

	// Another holder offers its own copy. The record is live and already holds
	// the rotated token, so nothing is written.
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-someone-elses"))

	rec, err := s.get(ctx, RecordID("user-1", "idp-1"))
	require.NoError(t, err)
	assert.Equal(t, "rt-rotated", rec.GetUpstreamRefreshToken(),
		"a live record keeps the token it rotated to")

	clk.Advance(time.Hour)
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	assert.Equal(t, "rt-rotated", auth.lastPresented(), "the rotated token is what gets presented")
}

// TestShortLivedTokensRefreshOnDemand covers a provider whose access tokens are
// shorter than the debounce window. Once a refresh has succeeded, the token that
// would be presented next is the successor that attempt committed, not the token
// it presented, so refreshing at expiry is ordinary behavior and the window does
// not hold it back. Debouncing here would leave the record expired and every
// caller refused for most of every window.
func TestShortLivedTokensRefreshOnDemand(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: 30 * time.Second, now: clk.Now}
	client := dbtestutil.NewTestDatabroker(t)
	get := newAuthGetter(auth)
	s1 := New(client, get, WithNow(clk.Now))
	s2 := New(client, get, WithNow(clk.Now))

	require.NoError(t, s1.Register(ctx, "user-1", "idp-1", "rt-1"))
	_, err := s1.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)

	// The token has expired well inside the debounce window.
	clk.Advance(time.Minute)
	require.Less(t, time.Minute, DefaultMinRefreshInterval+time.Minute)

	results := make(chan result, 2)
	var wg sync.WaitGroup
	start := time.Now()
	for _, s := range []*Store{s1, s2} {
		wg.Go(func() {
			live, err := s.EnsureLive(ctx, "user-1", "idp-1")
			results <- result{live, err}
		})
	}
	wg.Wait()
	elapsed := time.Since(start)
	close(results)

	for r := range results {
		require.NoError(t, r.err, "an expired token is refreshed, not refused")
		require.NotNil(t, r.live)
		assert.Equal(t, "at-2", r.live.Token.AccessToken, "both callers see the same new token")
	}
	assert.Less(t, elapsed, 5*time.Second, "both callers answer promptly")
	assert.Equal(t, int64(2), auth.callCount(),
		"the two replicas collapse to one presentation through the singleflight")
}

// mustRecord reads the canonical record, failing the test if it is not there.
func mustRecord(t *testing.T, ctx context.Context, s *Store, userID, idpID string) record {
	t.Helper()
	rec, err := s.get(ctx, RecordID(userID, idpID))
	require.NoError(t, err)
	return rec
}

// TestFailuresArePacedByTheRetryHint: the debounce window exists to stop
// repeated presentation of a token whose fate is unknown. After a failure the
// escalating retry hint already does that, and it grows, so the flat window is
// not applied as well: a provider whose access tokens are shorter than the
// window would otherwise be refused for the rest of every window after one
// hiccup.
func TestFailuresArePacedByTheRetryHint(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	// Ages are measured against the databroker's write timestamps, so a fake
	// clock that runs ahead of real time makes every record look old. This test
	// keeps the two together and gets an expired token from the provider instead
	// of by advancing.
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: -time.Second, now: clk.Now}
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, newAuthGetter(auth), WithNow(clk.Now))

	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))
	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)

	// The next refresh fails before the request leaves, so the token was
	// certainly not consumed and the intent is cleared with the failure.
	auth.setErr(&net.OpError{Op: "dial", Err: errors.New("connection refused")})
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.ErrorIs(t, err, ErrRefreshUnavailable)
	require.Equal(t, int64(2), auth.callCount())

	after, ok := RetryAfter(err)
	require.True(t, ok, "a transient error carries a retry hint")
	assert.Equal(t, DefaultRetryAfter, after, "the first failure asks for the floor")

	// Immediately afterwards the record is still held back.
	auth.setErr(nil)
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrRefreshUnavailable, "a failure paces the next attempt")
	assert.Equal(t, int64(2), auth.callCount())

	// Once the hint has elapsed the next caller may try again, well inside the
	// debounce window that would otherwise still be running.
	clk.Advance(after + time.Second)
	require.Less(t, time.Minute, DefaultMinRefreshInterval,
		"the point of this test is that the flat debounce window outlasts the hint")
	require.True(t, s.debounced(mustRecord(t, ctx, s, "user-1", "idp-1")),
		"the record is still inside the debounce window")
	live, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err, "the hint, not the window, paces recovery")
	assert.NotNil(t, live)
	assert.Equal(t, int64(3), auth.callCount())
}

// TestIntent_FreshForeignIntentWaitsThenReportsTransient: a caller that finds
// another caller's intent inside the settle window waits, then reports a
// transient error. Presenting the token itself would be a replay.
func TestIntent_FreshForeignIntentWaitsThenReportsTransient(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, newAuthGetter(auth), WithNow(clk.Now))

	id := RecordID("user-1", "idp-1")
	putRecord(ctx, t, client, &oauth21proto.UpstreamIdPSession{
		Id:                   id,
		UserId:               "user-1",
		IdpId:                "idp-1",
		UpstreamRefreshToken: "rt-1",
		State:                oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_LIVE,
		RefreshAttemptId:     "attempt-held-by-another-replica",
		RefreshStartedAt:     timestamppb.New(clk.Now()),
	})

	start := time.Now()
	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	elapsed := time.Since(start)

	assert.ErrorIs(t, err, ErrRefreshUnavailable)
	assert.NotErrorIs(t, err, ErrUpstreamSessionDead, "someone else working is not a sign-out")
	assert.Equal(t, int64(0), auth.callCount(), "the token belongs to the attempt that claimed it")
	assert.GreaterOrEqual(t, elapsed, pollMinDelay, "the caller waits for the holder to commit")
	assert.Less(t, elapsed, 30*time.Second, "and gives up inside a bounded budget")
}

// TestIntent_StaleIntentOnRotatingProviderDiesWithoutPresenting: on a provider
// observed to rotate, an abandoned attempt may already have consumed the token,
// so the record is retired locally. Re-presenting it to find out would revoke
// the family.
func TestIntent_StaleIntentOnRotatingProviderDiesWithoutPresenting(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	// Anchored at the real clock: the settle window runs from the databroker's
	// write timestamp, so the intent has to be aged by advancing past it rather
	// than by back-dating the field. See writeAnchor.
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, newAuthGetter(auth), WithNow(clk.Now))

	id := RecordID("user-1", "idp-1")
	putRecord(ctx, t, client, &oauth21proto.UpstreamIdPSession{
		Id:                   id,
		UserId:               "user-1",
		IdpId:                "idp-1",
		UpstreamRefreshToken: "rt-possibly-consumed",
		State:                oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_LIVE,
		Generation:           3,
		RotationObserved:     true,
		RefreshAttemptId:     "attempt-nobody-finished",
		RefreshStartedAt:     timestamppb.New(clk.Now()),
	})
	clk.Advance(settleDelay + time.Second)

	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrUpstreamSessionDead)
	assert.Equal(t, deadReasonUnknownOutcome, DeadReason(err))
	assert.Equal(t, int64(0), auth.callCount(), "resolution never contacts the IdP")

	// The resolution is committed, so every other replica sees the same answer.
	rec, err := s.get(ctx, id)
	require.NoError(t, err)
	assert.True(t, isDead(rec))
	assert.Equal(t, deadReasonUnknownOutcome, rec.GetDeadReason())
	assert.Empty(t, rec.GetRefreshAttemptId(), "the intent is resolved, not left dangling")
}

// TestIntent_StaleIntentOnNonRotatingProviderProbes: where a completed refresh
// has already returned the same refresh token, re-presentation is idempotent and
// the stale intent is recoverable rather than terminal. generation distinguishes
// that observation from a record that has never refreshed; see
// TestIntent_SeedWithLostFirstResponseDiesWithoutProbing.
func TestIntent_StaleIntentOnNonRotatingProviderProbes(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users:        []*mockidp.User{{Email: "user@example.com"}},
		RotationMode: mockidp.NonRotating,
	})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)
	clk := &fakeClock{t: time.Now()}
	s := New(client, getAuth, WithNow(clk.Now))

	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	id := RecordID("user-1", "idp-1")
	putRecord(ctx, t, client, &oauth21proto.UpstreamIdPSession{
		Id:                   id,
		UserId:               "user-1",
		IdpId:                "idp-1",
		UpstreamRefreshToken: rt,
		State:                oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_LIVE,
		// Two completed refreshes, neither of which rotated, so rotation_observed
		// being false is an observation rather than the absence of one.
		Generation:       2,
		RefreshedAt:      timestamppb.New(clk.Now().Add(-time.Hour)),
		RefreshAttemptId: "attempt-nobody-finished",
		RefreshStartedAt: timestamppb.New(clk.Now()),
	})
	clk.Advance(settleDelay + time.Second)

	live, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err, "a token that cannot be consumed by presenting it can be probed")
	assert.NotEmpty(t, live.Token.AccessToken)

	rec, err := s.get(ctx, id)
	require.NoError(t, err)
	assert.False(t, rec.GetRotationObserved(), "the provider still has not rotated anything")
	assert.Equal(t, rt, rec.GetUpstreamRefreshToken())
	assert.Empty(t, rec.GetRefreshAttemptId())
}

// TestIntent_SeedWithLostFirstResponseDiesWithoutProbing covers a seed whose
// first refresh response was lost. Nothing was observed: rotation_observed is
// false only because no refresh completed. Probing would re-present a token the
// IdP may already have consumed, and on a reuse-detecting provider that replay
// revokes the whole grant family, so the record is retired without contacting
// the IdP again and only a fresh login brings the pair back.
func TestIntent_SeedWithLostFirstResponseDiesWithoutProbing(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, 2*time.Minute)

	idp := mockidp.New(mockidp.Config{
		Users:        []*mockidp.User{{Email: "user@example.com"}},
		RotationMode: mockidp.RotateReuseDetect, // one replay ends the family
	})
	getAuth := realAuthenticator(t, idp)
	client := dbtestutil.NewTestDatabroker(t)
	clk := &fakeClock{t: time.Now()}
	s := New(client, getAuth, WithNow(clk.Now))

	// Warm the provider's client-auth style the way a deployment does, with the
	// login-time code exchange, so a failed refresh costs one POST rather than
	// two. See pkg/identity/oidc.Provider.GetOauthConfig.
	auth, err := getAuth(ctx, "idp-1")
	require.NoError(t, err)
	_, err = auth.Authenticate(ctx, idp.AuthCode("user@example.com", "test-client"), newClaimsCapture())
	require.NoError(t, err)
	idp.RevokeAllRefreshTokens()

	rt := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", rt))

	// The first refresh executes at the IdP, consuming the seed and minting a
	// successor, but the response is lost, so neither the successor nor whether
	// this provider rotates is learned.
	idp.DropNextRefreshResponse(1)
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRefreshUnavailable)
	assert.NotErrorIs(t, err, ErrUpstreamSessionDead, "an unobserved outcome is not a sign-out")
	require.Equal(t, int64(1), idp.RefreshCount(), "one presentation, one POST")

	// While the attempt could still land, nothing may touch the token.
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrRefreshUnavailable, "the intent holds every caller off the token")

	// Past the settle window the intent is resolved. A record at generation 0 has
	// no non-rotation observation to justify a probe, so it is retired without
	// contacting the IdP again.
	clk.Advance(settleDelay + time.Second)
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrUpstreamSessionDead)
	assert.Equal(t, deadReasonUnknownOutcome, DeadReason(err))
	assert.Equal(t, int64(1), idp.RefreshCount(), "the seed is never presented a second time")
	assert.False(t, idp.IsRefreshTokenValid(rt), "the IdP did consume it, which is the risk being covered")
	assert.Equal(t, 1, idp.ValidRefreshTokenCount(),
		"the orphaned successor is stranded, but no replay means the family was never revoked")

	// Death is absolute: the holder of the consumed seed cannot revive it, and
	// neither can any other copy.
	assert.ErrorIs(t, s.Register(ctx, "user-1", "idp-1", rt), ErrUpstreamSessionDead)

	// Signing in again does.
	fresh := idp.IssueRefreshToken("user@example.com", "test-client")
	require.NoError(t, s.Supersede(ctx, "user-1", "idp-1", fresh, "id-token-from-login"))
	live, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err, "a fresh grant brings the pair back")
	assert.NotEmpty(t, live.Token.AccessToken)
}

// TestLegacyRecordRefreshes: records written before state and generation existed
// read as LIVE and refresh normally, so the upgrade needs no migration.
func TestLegacyRecordRefreshes(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, newAuthGetter(auth), WithNow(clk.Now))

	id := RecordID("user-1", "idp-1")
	putRecord(ctx, t, client, &oauth21proto.UpstreamIdPSession{
		Id:                   id,
		UserId:               "user-1",
		IdpId:                "idp-1",
		UpstreamRefreshToken: "rt-legacy",
		// no state, no generation, no intent: everything a pre-upgrade write had
	})

	live, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	assert.NotNil(t, live)
	assert.Equal(t, "rt-legacy", auth.lastPresented())

	rec, err := s.get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_LIVE, rec.GetState(),
		"the first write after the upgrade records the previously implied state")
	assert.Equal(t, uint64(1), rec.GetGeneration())
}

// TestClassify covers the mapping from a refresh error to what the store is
// allowed to conclude, directly. The end-to-end tests exercise a few of these
// arms through the store, but the classification is what decides whether a
// record is retired, and the branches that must not retire one are the branches
// least likely to be reached by an end-to-end test.
func TestClassify(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)

	retrieve := func(code string, status int) error {
		return &oauth2.RetrieveError{
			Response:  &http.Response{StatusCode: status},
			ErrorCode: code,
		}
	}

	for _, tc := range []struct {
		name string
		err  error
		want refreshClass
	}{
		{"nothing was sent", errNotSent, classKnownFailed},
		{"invalid_grant is the provider ending the grant", invalidGrant(), classPermanent},
		{
			// A rotated client secret must not sign out every user of the
			// deployment: the grants are intact, Pomerium's credentials are not.
			"invalid_client keeps the sessions",
			retrieve("invalid_client", http.StatusUnauthorized),
			classKnownFailed,
		},
		{"unauthorized_client keeps the sessions", retrieve("unauthorized_client", http.StatusBadRequest), classKnownFailed},
		{"invalid_request keeps the sessions", retrieve("invalid_request", http.StatusBadRequest), classKnownFailed},
		{"a 500 from the provider itself", retrieve("", http.StatusInternalServerError), classKnownFailed},
		{"rate limiting", retrieve("", http.StatusTooManyRequests), classKnownFailed},
		{"a gateway answered for the provider", retrieve("", http.StatusBadGateway), classAmbiguous},
		{"a gateway timed out", retrieve("", http.StatusGatewayTimeout), classAmbiguous},
		{"dns did not resolve", &net.DNSError{Err: "no such host"}, classKnownFailed},
		{"the connection was refused", &net.OpError{Op: "dial", Err: errors.New("connection refused")}, classKnownFailed},
		{"the deadline passed with the request in flight", context.DeadlineExceeded, classAmbiguous},
		{"the response was truncated", io.ErrUnexpectedEOF, classAmbiguous},
		{"an unrecognized error says nothing", errors.New("something else"), classAmbiguous},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, classify(ctx, tc.err), "classify(%v)", tc.err)
		})
	}
}
