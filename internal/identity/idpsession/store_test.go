package idpsession

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/internal/testutil"
	dbtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	databroker_grpc "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// --- test harness -----------------------------------------------------------

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// invalidGrant is the IdP's RFC 6749 refusal of a refresh token, the only error
// the store treats as a permanent end of the upstream session.
func invalidGrant() error {
	return &oauth2.RetrieveError{
		Response:  &http.Response{StatusCode: http.StatusBadRequest},
		ErrorCode: "invalid_grant",
	}
}

// temporaryError has Temporary() == true, so the store treats it as transient.
type temporaryError struct{}

func (temporaryError) Error() string   { return "temporary" }
func (temporaryError) Temporary() bool { return true }

// fakeAuth is a minimal identity.Authenticator whose Refresh is programmable and
// call-counted, so tests can assert how many times the IdP was called.
type fakeAuth struct {
	// Embedded so only Refresh has to be implemented. Anything else this test
	// package starts calling panics loudly rather than returning a quiet stub.
	identity.Authenticator

	mu             sync.Mutex
	calls          int64
	err            error         // if set, Refresh returns this
	lifetime       time.Duration // token lifetime from now()
	now            func() time.Time
	rotateTo       string // if set, returned token carries this refresh token
	lastOldRefresh string // the refresh token presented on the last Refresh
	rawIDToken     string
	claimsJSON     string
	block          chan struct{} // if non-nil, Refresh blocks on it (concurrency test)
}

func (f *fakeAuth) Refresh(_ context.Context, t *oauth2.Token, v identity.State) (*oauth2.Token, error) {
	atomic.AddInt64(&f.calls, 1)
	// Every field is read under the lock: the store commits outcomes on a
	// detached goroutine, so a test that changes a field after its call returned
	// can still be racing an attempt that is on its way out.
	f.mu.Lock()
	f.lastOldRefresh = t.RefreshToken
	blk, err := f.block, f.err
	rawIDToken, claimsJSON, rotateTo, lifetime := f.rawIDToken, f.claimsJSON, f.rotateTo, f.lifetime
	f.mu.Unlock()
	if blk != nil {
		<-blk
	}
	if err != nil {
		return nil, err
	}
	if v != nil {
		v.SetRawIDToken(rawIDToken)
		if u, ok := v.(json.Unmarshaler); ok && claimsJSON != "" {
			_ = u.UnmarshalJSON([]byte(claimsJSON))
		}
	}
	n := atomic.LoadInt64(&f.calls)
	tok := &oauth2.Token{AccessToken: "at-" + strconv.FormatInt(n, 10), TokenType: "Bearer", Expiry: f.now().Add(lifetime)}
	if rotateTo != "" {
		tok.RefreshToken = rotateTo
	}
	return tok, nil
}

func (f *fakeAuth) callCount() int64 { return atomic.LoadInt64(&f.calls) }

// setErr changes what Refresh returns from now on.
func (f *fakeAuth) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

// lastPresented returns the refresh token given to the most recent Refresh.
func (f *fakeAuth) lastPresented() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastOldRefresh
}

func newTestStore(t *testing.T, auth *fakeAuth, clk *fakeClock, opts ...Option) *Store {
	t.Helper()
	client := dbtestutil.NewTestDatabroker(t)
	base := []Option{WithNow(clk.Now)}
	return New(client, newAuthGetter(auth), append(base, opts...)...)
}

func newAuthGetter(auth *fakeAuth) AuthenticatorGetter {
	return func(context.Context, string) (identity.Authenticator, error) { return auth, nil }
}

// --- tests ------------------------------------------------------------------

func TestEnsureLive_NoRecord(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	s := newTestStore(t, auth, clk)

	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrNoUpstreamSession)
	assert.Equal(t, int64(0), auth.callCount(), "must not hit IdP when no record exists")
}

func TestRegisterThenEnsureLive_RefreshesOnceThenFastPaths(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now, rawIDToken: "raw", claimsJSON: `{"email":"a@b.com","groups":["g1"]}`}
	s := newTestStore(t, auth, clk)

	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	live, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	require.NotNil(t, live)
	assert.Equal(t, int64(1), auth.callCount())
	assert.Equal(t, "at-1", live.Token.AccessToken)
	assert.Equal(t, "raw", live.RawIDToken)
	assert.Equal(t, []any{"a@b.com"}, live.Claims["email"])

	// Within the token's lifetime, subsequent calls fast-path with no IdP hit.
	for range 5 {
		clk.Advance(time.Minute)
		live, err = s.EnsureLive(ctx, "user-1", "idp-1")
		require.NoError(t, err)
		assert.Equal(t, "at-1", live.Token.AccessToken)
	}
	assert.Equal(t, int64(1), auth.callCount(), "fan-out of polls must not amplify IdP calls")
}

func TestEnsureLive_RefreshesAgainNearExpiry(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	s := newTestStore(t, auth, clk)
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), auth.callCount())

	// Advance past (lifetime - grace): the stored token is now stale → refresh.
	clk.Advance(time.Hour)
	live, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	assert.Equal(t, int64(2), auth.callCount())
	assert.Equal(t, "at-2", live.Token.AccessToken)
}

func TestEnsureLive_ConcurrentSingleflight(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now, block: make(chan struct{})}
	s := newTestStore(t, auth, clk)
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	const n = 50
	var wg sync.WaitGroup
	wg.Add(n)
	started := make(chan struct{}, n)
	results := make(chan result, n)
	for range n {
		go func() {
			defer wg.Done()
			started <- struct{}{}
			live, err := s.EnsureLive(ctx, "user-1", "idp-1")
			results <- result{live, err}
		}()
	}
	for range n {
		<-started
	}
	time.Sleep(100 * time.Millisecond) // let the followers queue on singleflight
	close(auth.block)
	wg.Wait()
	close(results)

	assert.Equal(t, int64(1), auth.callCount(), "singleflight must collapse concurrent callers to one IdP call")

	// What every caller got back matters as much as how many calls were made: a
	// store that collapsed them by refusing everyone would also pass a bare call
	// count.
	var served int
	for r := range results {
		if r.err != nil {
			// A suppressed caller may be told to retry, but never that its grant
			// is over.
			assert.True(t, IsTemporary(r.err), "a suppressed caller gets a retryable error, got %v", r.err)
			continue
		}
		served++
		require.NotNil(t, r.live)
		assert.Equal(t, "at-1", r.live.Token.AccessToken, "every served caller sees the one refreshed token")
	}
	assert.Positive(t, served, "the collapse must serve callers, not just suppress them")
}

func TestEnsureLive_PermanentError_MarksDead(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now, err: invalidGrant()}
	s := newTestStore(t, auth, clk)
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrUpstreamSessionDead)

	// Death is committed as state, not as a deleted record, so every later
	// consumer is told the session is over instead of re-seeding its own copy.
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrUpstreamSessionDead)
	assert.Equal(t, int64(1), auth.callCount(), "a dead record is answered without touching the IdP")
}

// TestEnsureLive_AmbiguousError_KeepsRecord covers a failure whose outcome was
// never observed. The token may or may not have been consumed, so the intent
// stays and nothing presents it again until the settle window passes.
func TestEnsureLive_AmbiguousError_KeepsRecord(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	// Ages come from the databroker's write timestamps, so advancing the fake
	// clock ahead of real time would make every record look old. The clock is
	// kept in step and staleness comes from the provider handing back tokens
	// that are already expired.
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: -time.Second, now: clk.Now}
	s := newTestStore(t, auth, clk)
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	// One completed refresh that returned no new refresh token, so the record has
	// observed that this provider does not rotate. That is what later makes
	// re-presenting the token a recovery rather than a replay.
	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)

	auth.setErr(temporaryError{})

	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrUpstreamSessionDead, "a transient blip must not kill the session")
	assert.ErrorIs(t, err, ErrRefreshUnavailable)
	assert.True(t, IsTemporary(err), "callers keep the session on a temporary error")

	// The IdP recovers, but the unresolved intent still holds every caller off
	// the token: an attempt that never reported an outcome may still be answered.
	auth.setErr(nil)
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.ErrorIs(t, err, ErrRefreshUnavailable, "the token stays untouched while its outcome may land")
	require.Equal(t, int64(2), auth.callCount())

	// Only once nothing can still be in flight does the record recover, and only
	// because every completed refresh on this family returned the same token, so
	// presenting it again is idempotent. A family observed to rotate is retired
	// instead; see TestContention_LostResponseDiesLabeledWithoutReplay.
	clk.Advance(settleDelay + time.Second)
	live, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err, "a non-rotating family is recoverable by probing")
	assert.NotNil(t, live)
	assert.Equal(t, int64(3), auth.callCount())
}

// TestEnsureLive_PreSendError_ClearsIntent covers a failure that never reached
// the IdP. The token was not consumed, so the next caller may retry immediately
// instead of waiting out the settle window.
func TestEnsureLive_PreSendError_ClearsIntent(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{
		lifetime: time.Hour, now: clk.Now,
		err: &net.OpError{Op: "dial", Err: errors.New("connection refused")},
	}
	s := newTestStore(t, auth, clk)
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	assert.ErrorIs(t, err, ErrRefreshUnavailable)
	assert.NotErrorIs(t, err, ErrUpstreamSessionDead)

	auth.setErr(nil)
	live, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err, "a request that never left may be retried immediately")
	assert.NotNil(t, live)
}

func TestEnsureLive_RotatesRefreshToken(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now, rotateTo: "rt-2"}
	s := newTestStore(t, auth, clk)
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	assert.Equal(t, "rt-1", auth.lastPresented(), "first refresh presents the seeded token")

	// Next refresh must present the rotated token, proving the store persisted it.
	clk.Advance(time.Hour)
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	assert.Equal(t, "rt-2", auth.lastPresented(), "store must present the rotated refresh token")
}

func TestEnsureLive_CrossProcessDebounce(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	client := dbtestutil.NewTestDatabroker(t)
	get := func(context.Context, string) (identity.Authenticator, error) { return auth, nil }

	// Two independent Store instances (simulating two proxy processes) share one DB.
	s1 := New(client, get, WithNow(clk.Now))
	s2 := New(client, get, WithNow(clk.Now))

	require.NoError(t, s1.Register(ctx, "user-1", "idp-1", "rt-1"))
	_, err := s1.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	// s2 reads the record s1 wrote; the token is fresh → no additional IdP hit.
	_, err = s2.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)

	assert.Equal(t, int64(1), auth.callCount(), "a second process must reuse the freshly refreshed record")
}

// TestStore_DatabrokerFailuresAreTransient: databrokerutil reports failures as
// typed gRPC status errors, none of which implement Temporary(). Passed through
// unchanged they would read as a refused grant, so every store entry point has
// to report them as retryable instead.
func TestStore_DatabrokerFailuresAreTransient(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)

	// Two classes, and the difference matters. A torn-down stream says nothing
	// about the record, so the store opens the flight again; anything else is an
	// answer, and is reported without retrying. Both end as retryable errors, so
	// asserting only that would not tell them apart.
	for _, tc := range []struct {
		code    codes.Code
		retried bool
	}{
		{codes.Unavailable, true},
		{codes.Aborted, true},
		{codes.Canceled, true},
		{codes.DeadlineExceeded, false},
		{codes.Internal, false},
		{codes.FailedPrecondition, false},
	} {
		t.Run(tc.code.String(), func(t *testing.T) {
			t.Parallel()
			clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
			auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
			counting := &countingTransactions{
				DataBrokerServiceClient: dbtestutil.FailingDatabroker(
					dbtestutil.NewTestDatabroker(t), status.Error(tc.code, "databroker is down")),
			}
			s := New(counting, newAuthGetter(auth), WithNow(clk.Now))

			for name, err := range map[string]error{
				"EnsureLive": func() error { _, e := s.EnsureLive(ctx, "user-1", "idp-1"); return e }(),
				"Register":   s.Register(ctx, "user-1", "idp-1", "rt-1"),
				"Revoke":     s.Revoke(ctx, "user-1", "idp-1"),
			} {
				require.Error(t, err, name)
				assert.True(t, IsTemporary(err), "%s: %v must be retryable", name, err)
				assert.ErrorIs(t, err, ErrRefreshUnavailable, name)
				assert.NotErrorIs(t, err, ErrUpstreamSessionDead, name)
				assert.NotErrorIs(t, err, ErrNoUpstreamSession, name)
				after, ok := RetryAfter(err)
				assert.True(t, ok, "%s: the caller is told when to come back", name)
				assert.Positive(t, after, name)
			}

			// Register opens exactly one flight per attempt, so its count is the
			// clean measure of whether the failure was retried.
			counting.reset()
			require.Error(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))
			attempts := counting.count()
			if tc.retried {
				assert.Greater(t, attempts, 1,
					"a torn-down stream is worth opening the flight again")
			} else {
				assert.Equal(t, 1, attempts,
					"an answer from the databroker is reported, not retried")
			}
		})
	}
}

// countingTransactions counts how many flights were opened, so a test can tell
// a retried failure from one reported immediately.
type countingTransactions struct {
	databroker_grpc.DataBrokerServiceClient
	mu sync.Mutex
	n  int
}

func (c *countingTransactions) Transaction(
	ctx context.Context, opts ...grpc.CallOption,
) (grpc.BidiStreamingClient[databroker_grpc.TransactionStreamRequest, databroker_grpc.TransactionStreamResponse], error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return c.DataBrokerServiceClient.Transaction(ctx, opts...)
}

func (c *countingTransactions) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func (c *countingTransactions) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n = 0
}

// TestStore_PublishesRecordTTL checks the store registers the record type's TTL
// with the databroker. Enforcement of that TTL is the backends' job and is
// covered by their own tests.
func TestStore_PublishesRecordTTL(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, newAuthGetter(auth), WithNow(clk.Now))

	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	res, err := client.GetOptions(ctx, &databroker_grpc.GetOptionsRequest{
		Type: recordTypeURL,
	})
	require.NoError(t, err)
	assert.Equal(t, 90*24*time.Hour, res.GetOptions().GetTtl().AsDuration(),
		"the canonical record type must carry a 90 day ttl")

	// Setting the options again on a later operation is harmless and must not
	// change what was published.
	require.NoError(t, s.Revoke(ctx, "user-1", "idp-1"))
	res, err = client.GetOptions(ctx, &databroker_grpc.GetOptionsRequest{
		Type: recordTypeURL,
	})
	require.NoError(t, err)
	assert.Equal(t, recordTTL, res.GetOptions().GetTtl().AsDuration())
}

func TestRecordIDDeterministic(t *testing.T) {
	t.Parallel()
	a := RecordID("user-1", "idp-1")
	b := RecordID("user-1", "idp-1")
	assert.Equal(t, a, b, "same (user, idp) must map to the same record id")
	assert.NotEqual(t, a, RecordID("user-2", "idp-1"), "different users must map to different record ids")
	assert.NotEqual(t, a, RecordID("user-1", "idp-2"), "different idps must map to different record ids")
}

// TestRetryAfterEscalates: a cause no retry can fix, such as Pomerium's own
// client credentials being wrong, must not have every consumer of the user
// asking again every few seconds forever.
func TestRetryAfterEscalates(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{
		lifetime: time.Hour, now: clk.Now,
		err: &oauth2.RetrieveError{
			Response:  &http.Response{StatusCode: http.StatusUnauthorized},
			ErrorCode: "invalid_client",
		},
	}
	s := newTestStore(t, auth, clk)
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	var hints []time.Duration
	for range 4 {
		_, err := s.EnsureLive(ctx, "user-1", "idp-1")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrUpstreamSessionDead,
			"pomerium's own misconfiguration must never revoke a user's session")
		after, ok := RetryAfter(err)
		require.True(t, ok, "a transient error carries a retry hint")
		hints = append(hints, after)
		// Leave the debounce window so the next call reaches the IdP again.
		clk.Advance(DefaultMinRefreshInterval + time.Second)
	}

	assert.Equal(t, DefaultRetryAfter, hints[0], "the first failure asks for the floor")
	for i := 1; i < len(hints); i++ {
		assert.Greater(t, hints[i], hints[i-1], "repeated failures back off: %v", hints)
	}
	assert.LessOrEqual(t, hints[len(hints)-1], maxRetryAfter)
}

func TestRetryAfterFor(t *testing.T) {
	t.Parallel()
	assert.Equal(t, DefaultRetryAfter, retryAfterFor(0))
	assert.Equal(t, DefaultRetryAfter, retryAfterFor(1))
	assert.Equal(t, 2*DefaultRetryAfter, retryAfterFor(2))
	assert.Equal(t, 4*DefaultRetryAfter, retryAfterFor(3))
	assert.Equal(t, maxRetryAfter, retryAfterFor(100), "the backoff is capped")
}

// TestRequireFresh: without it a caller is served any unexpired token, so a
// revoked upstream session keeps looking alive until that token expires. With
// it, liveness is rechecked once per debounce window.
func TestRequireFresh(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	s := newTestStore(t, auth, clk)
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	_, err := s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	require.Equal(t, int64(1), auth.callCount())

	// Inside the debounce window both modes are served from the record.
	_, err = s.EnsureLive(ctx, "user-1", "idp-1", RequireFresh())
	require.NoError(t, err)
	assert.Equal(t, int64(1), auth.callCount(), "the window still collapses callers")

	// Past the window the plain caller keeps the unexpired token, while the
	// caller asking for freshness goes back to the IdP.
	clk.Advance(DefaultMinRefreshInterval + time.Second)
	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), auth.callCount(), "an unexpired token satisfies a plain caller")

	_, err = s.EnsureLive(ctx, "user-1", "idp-1", RequireFresh())
	require.NoError(t, err)
	assert.Equal(t, int64(2), auth.callCount(), "freshness is rechecked once per window")

	// A revocation is therefore seen within a window rather than at expiry.
	auth.setErr(invalidGrant())
	clk.Advance(DefaultMinRefreshInterval + time.Second)
	_, err = s.EnsureLive(ctx, "user-1", "idp-1", RequireFresh())
	assert.ErrorIs(t, err, ErrUpstreamSessionDead)
}

// TestUndecodableRecordIsNotTransient: bytes that do not parse cannot be fixed
// by retrying, so they must not be reported as a retryable failure and loop.
func TestUndecodableRecordIsNotTransient(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, newAuthGetter(auth), WithNow(clk.Now))

	// Store something under the canonical id whose payload is a different type.
	id := RecordID("user-1", "idp-1")
	data := protoutil.NewAny(&oauth21proto.MCPRefreshToken{Id: id})
	_, err := client.Put(ctx, &databroker_grpc.PutRequest{Records: []*databroker_grpc.Record{{
		Id:   id,
		Data: data,
		Type: recordTypeURL,
	}}})
	require.NoError(t, err)

	_, err = s.EnsureLive(ctx, "user-1", "idp-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrRecordUndecodable)
	assert.False(t, IsTemporary(err), "retrying cannot repair stored bytes")
	assert.NotErrorIs(t, err, ErrUpstreamSessionDead)
	assert.NotErrorIs(t, err, ErrNoUpstreamSession)
	assert.Equal(t, int64(0), auth.callCount())
}

// TestDeathIsAbsolute pins the second invariant: no copy of a token revives a
// dead record, whatever killed it. Only Supersede does, and only the login flow
// calls Supersede, because a login is the one event that produces a token no
// consumer could have been holding since before the record died.
func TestDeathIsAbsolute(t *testing.T) {
	t.Parallel()

	// Each case drives a record to one dead reason and returns the store.
	kill := map[string]func(t *testing.T, ctx context.Context) *Store{
		deadReasonIDPRevoked: func(t *testing.T, ctx context.Context) *Store {
			clk := &fakeClock{t: time.Now()}
			auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
			s := newTestStore(t, auth, clk)
			require.NoError(t, s.Register(ctx, "u", "i", "rt-held"))
			_, err := s.EnsureLive(ctx, "u", "i")
			require.NoError(t, err)
			clk.Advance(time.Hour)
			auth.setErr(invalidGrant())
			_, err = s.EnsureLive(ctx, "u", "i")
			require.ErrorIs(t, err, ErrUpstreamSessionDead)
			require.Equal(t, deadReasonIDPRevoked, DeadReason(err))
			return s
		},
		deadReasonSeedInvalid: func(t *testing.T, ctx context.Context) *Store {
			clk := &fakeClock{t: time.Now()}
			auth := &fakeAuth{lifetime: time.Hour, now: clk.Now, err: invalidGrant()}
			s := newTestStore(t, auth, clk)
			require.NoError(t, s.Register(ctx, "u", "i", "rt-held"))
			_, err := s.EnsureLive(ctx, "u", "i")
			require.ErrorIs(t, err, ErrUpstreamSessionDead)
			require.Equal(t, deadReasonSeedInvalid, DeadReason(err))
			return s
		},
		deadReasonUnknownOutcome: func(t *testing.T, ctx context.Context) *Store {
			clk := &fakeClock{t: time.Now()}
			auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
			client := dbtestutil.NewTestDatabroker(t)
			s := New(client, newAuthGetter(auth), WithNow(clk.Now))
			id := RecordID("u", "i")
			putRecord(ctx, t, client, &oauth21proto.UpstreamIdPSession{
				Id: id, UserId: "u", IdpId: "i",
				UpstreamRefreshToken: "rt-held",
				State:                oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_LIVE,
				Generation:           3,
				RotationObserved:     true,
				RefreshAttemptId:     "attempt-nobody-finished",
				RefreshStartedAt:     timestamppb.New(clk.Now()),
			})
			clk.Advance(settleDelay + time.Second)
			_, err := s.EnsureLive(ctx, "u", "i")
			require.ErrorIs(t, err, ErrUpstreamSessionDead)
			require.Equal(t, deadReasonUnknownOutcome, DeadReason(err))
			return s
		},
		deadReasonPomeriumSignout: func(t *testing.T, ctx context.Context) *Store {
			clk := &fakeClock{t: time.Now()}
			auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
			s := newTestStore(t, auth, clk)
			require.NoError(t, s.Register(ctx, "u", "i", "rt-held"))
			require.NoError(t, s.Revoke(ctx, "u", "i"))
			return s
		},
	}

	for reason, drive := range kill {
		t.Run(reason, func(t *testing.T) {
			t.Parallel()
			ctx := testutil.GetContext(t, time.Minute)
			s := drive(t, ctx)

			// Neither the token the record died holding nor any other copy of it
			// brings the record back.
			assert.ErrorIs(t, s.Register(ctx, "u", "i", "rt-held"), ErrUpstreamSessionDead)
			assert.ErrorIs(t, s.Register(ctx, "u", "i", "rt-some-other-copy"), ErrUpstreamSessionDead)
			_, err := s.EnsureLive(ctx, "u", "i")
			assert.ErrorIs(t, err, ErrUpstreamSessionDead)

			// A fresh grant does, and starts a new epoch.
			require.NoError(t, s.Supersede(ctx, "u", "i", "rt-from-a-new-login", "id-token-from-login"))
			rec, err := s.get(ctx, RecordID("u", "i"))
			require.NoError(t, err)
			assert.Equal(t, oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_LIVE, rec.GetState())
			assert.Equal(t, "rt-from-a-new-login", rec.GetUpstreamRefreshToken())
			assert.Equal(t, uint64(0), rec.GetGeneration(), "a new epoch counts its own rotations")
			assert.False(t, rec.GetRotationObserved(), "nothing is yet known about the new family")
		})
	}
}

// TestLegacyIntentWithNoStartTimeAges: a record written by something that
// stamped no start time still ages, because the databroker's own write timestamp
// is always there. Treating it as permanently in flight made it unrecoverable.
func TestLegacyIntentWithNoStartTimeAges(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, newAuthGetter(auth), WithNow(clk.Now))

	id := RecordID("u", "i")
	putRecord(ctx, t, client, &oauth21proto.UpstreamIdPSession{
		Id: id, UserId: "u", IdpId: "i",
		UpstreamRefreshToken: "rt-1",
		State:                oauth21proto.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_LIVE,
		Generation:           2,
		RefreshedAt:          timestamppb.New(clk.Now().Add(-time.Hour)),
		RefreshAttemptId:     "written-without-a-start-time",
		// no RefreshStartedAt
	})

	_, err := s.EnsureLive(ctx, "u", "i")
	require.ErrorIs(t, err, ErrRefreshUnavailable, "held off while the intent could still be answered")

	clk.Advance(settleDelay + time.Second)
	live, err := s.EnsureLive(ctx, "u", "i")
	require.NoError(t, err, "the intent aged out on the databroker's write timestamp")
	assert.NotNil(t, live)
}

// TestRequireFreshNeverServesAnExpiredToken: a provider whose access tokens are
// shorter than the debounce window would otherwise have an expired token served
// into whatever the caller mints from it.
func TestRequireFreshNeverServesAnExpiredToken(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: 30 * time.Second, now: clk.Now}
	s := newTestStore(t, auth, clk)
	require.NoError(t, s.Register(ctx, "u", "i", "rt-1"))

	live, err := s.EnsureLive(ctx, "u", "i", RequireFresh())
	require.NoError(t, err)
	require.Equal(t, int64(1), auth.callCount())
	require.True(t, live.Token.Expiry.After(clk.Now()))

	// Still inside the debounce window, but the token has expired.
	clk.Advance(45 * time.Second)
	stored, err := s.get(ctx, RecordID("u", "i"))
	require.NoError(t, err)
	require.True(t, s.debounced(stored), "still within the debounce window")

	live, err = s.EnsureLive(ctx, "u", "i", RequireFresh())
	require.NoError(t, err)
	assert.Equal(t, int64(2), auth.callCount(), "an expired token is refreshed, not served")
	assert.True(t, live.Token.Expiry.After(clk.Now()), "the caller never receives an expired token")
}

// TestSupersedeReplacesAnUnreadableRecord: stored bytes that do not parse are
// refused by every read, and under strict semantics no held copy may overwrite
// them. A login can, which keeps the pair recoverable instead of stuck until the
// record's TTL.
func TestSupersedeReplacesAnUnreadableRecord(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	client := dbtestutil.NewTestDatabroker(t)
	s := New(client, newAuthGetter(auth), WithNow(clk.Now))

	id := RecordID("u", "i")
	_, err := client.Put(ctx, &databroker_grpc.PutRequest{Records: []*databroker_grpc.Record{{
		Id:   id,
		Data: protoutil.NewAny(&oauth21proto.MCPRefreshToken{Id: id}),
		Type: recordTypeURL,
	}}})
	require.NoError(t, err)

	_, err = s.EnsureLive(ctx, "u", "i")
	require.ErrorIs(t, err, ErrRecordUndecodable)
	require.False(t, IsTemporary(err), "retrying cannot repair stored bytes")

	// A holder of a copy cannot overwrite what it cannot read.
	require.ErrorIs(t, s.Register(ctx, "u", "i", "rt-1"), ErrRecordUndecodable)

	require.NoError(t, s.Supersede(ctx, "u", "i", "rt-from-a-new-login", "id-token-from-login"),
		"a fresh grant replaces an unreadable record")

	live, err := s.EnsureLive(ctx, "u", "i")
	require.NoError(t, err)
	assert.NotNil(t, live)
	assert.Equal(t, "rt-from-a-new-login", auth.lastPresented())
}

// TestCacheAuthenticators: the store calls the getter on every refresh, and a
// getter that rebuilds a provider each time throws away the client-auth style
// that provider learned, which is what makes x/oauth2 re-probe and re-POST a
// failed refresh with the other style.
func TestCacheAuthenticators(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)
	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}

	var built atomic.Int64
	get := CacheAuthenticators(func(context.Context, string) (identity.Authenticator, error) {
		built.Add(1)
		return auth, nil
	})

	s := New(dbtestutil.NewTestDatabroker(t), get, WithNow(clk.Now), WithMinRefreshInterval(0))
	require.NoError(t, s.Register(ctx, "user-1", "idp-1", "rt-1"))

	// RequireFresh with no debounce window means every call presents, which is
	// what makes the count below measure the getter rather than the cache in
	// front of it.
	for range 5 {
		_, err := s.EnsureLive(ctx, "user-1", "idp-1", RequireFresh())
		require.NoError(t, err)
	}
	require.Equal(t, int64(5), auth.callCount(), "each call really did present upstream")
	assert.EqualValues(t, 1, built.Load(), "the provider is built once per idp, not per refresh")

	// A different provider is resolved separately.
	require.NoError(t, s.Register(ctx, "user-1", "idp-2", "rt-2"))
	_, err := s.EnsureLive(ctx, "user-1", "idp-2", RequireFresh())
	require.NoError(t, err)
	assert.EqualValues(t, 2, built.Load(), "a second idp gets its own provider")
}
