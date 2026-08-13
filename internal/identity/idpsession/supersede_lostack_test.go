package idpsession

// Store.do retries a flight whose acknowledgement was lost, so every callback it
// runs has to be safe against its own committed effect. Most are idempotent by
// construction: Register re-reads and finds the record it wrote, Revoke finds it
// already dead, the attempt commit fails its ownership check. Supersede is the
// one that writes unconditionally, and this pins the guard that makes it safe.
//
// Without that guard: the login's write commits, its acknowledgement is lost,
// and before the retry fires an EnsureLive claims an intent on the new token and
// goes to the IdP. The retry then rewrites a fresh record with no intent, so the
// next caller claims and presents the same token a second time while the first
// presentation is still outstanding. On a reuse-detecting provider that revokes
// the family the user just signed in to create.

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/testutil"
	dbtestutil "github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// lostAckClient drops the acknowledgement of exactly one committed transaction,
// which is what a torn-down stream does. The server has already committed by
// the time it sends that response, so this is a lost ack and not a lost write.
type lostAckClient struct {
	databrokerpb.DataBrokerServiceClient
	arm       atomic.Bool
	onLostAck func()
}

func (c *lostAckClient) Transaction(
	ctx context.Context, opts ...grpc.CallOption,
) (grpc.BidiStreamingClient[databrokerpb.TransactionStreamRequest, databrokerpb.TransactionStreamResponse], error) {
	st, err := c.DataBrokerServiceClient.Transaction(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return &lostAckStream{BidiStreamingClient: st, owner: c}, nil
}

type lostAckStream struct {
	grpc.BidiStreamingClient[databrokerpb.TransactionStreamRequest, databrokerpb.TransactionStreamResponse]
	owner      *lostAckClient
	sentCommit bool
}

func (s *lostAckStream) Send(req *databrokerpb.TransactionStreamRequest) error {
	if req.GetCommit() != nil {
		s.sentCommit = true
	}
	return s.BidiStreamingClient.Send(req)
}

func (s *lostAckStream) Recv() (*databrokerpb.TransactionStreamResponse, error) {
	res, err := s.BidiStreamingClient.Recv()
	if err != nil || !s.sentCommit || !s.owner.arm.CompareAndSwap(true, false) {
		return res, err
	}
	// The server committed and answered; the answer is lost on the way back.
	if s.owner.onLostAck != nil {
		s.owner.onLostAck()
	}
	return nil, status.Error(codes.Unavailable, "connection reset by peer")
}

func TestSupersedeRetryAfterLostAckIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)

	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	raw := dbtestutil.NewTestDatabroker(t)
	lossy := &lostAckClient{DataBrokerServiceClient: raw}

	// The login flow's store: no authenticator, so it can only Supersede.
	login := New(lossy, nil, WithNow(clk.Now))
	// Another replica, serving EnsureLive over the same databroker.
	replica := New(raw, newAuthGetter(auth), WithNow(clk.Now))

	id := RecordID("u", "i")

	lost := make(chan struct{})
	claimDone := make(chan outcome, 1)
	lossy.onLostAck = func() { close(lost) }

	go func() {
		select {
		case <-lost:
		case <-ctx.Done():
			return
		}
		// The Supersede is committed and Store.do is about to wait a jittered
		// 250-1250ms before retrying. A liveness check on another replica claims
		// the intent in that window and goes to the IdP.
		out, err := replica.claim(ctx, id, liveOptions{})
		if err != nil {
			claimDone <- outcome{}
			return
		}
		claimDone <- out
	}()

	lossy.arm.Store(true)
	require.NoError(t, login.Supersede(ctx, "u", "i", "rt-login", "id-token-from-login"),
		"the write did commit; only its acknowledgement was lost")

	var claimed outcome
	select {
	case claimed = <-claimDone:
	case <-time.After(20 * time.Second):
		t.Fatal("the interleaved claim never ran")
	}
	require.Equal(t, outcomeClaimed, claimed.kind, "the interleaved caller did commit an intent")
	require.NotEmpty(t, claimed.rec.GetRefreshAttemptId())

	after, err := replica.get(ctx, id)
	require.NoError(t, err)
	t.Logf("after the retry: epoch=%d attempt=%q token=%q",
		after.GetEpoch(), after.GetRefreshAttemptId(), after.GetUpstreamRefreshToken())

	assert.Equal(t, claimed.rec.GetRefreshAttemptId(), after.GetRefreshAttemptId(),
		"a retried write whose first attempt already committed must not clear an intent "+
			"committed in between: the attempt holding it is at the IdP with this very token")

	assert.NotEqual(t, "claim", func() string {
		switch replica.decide(after, liveOptions{}).kind {
		case outcomeClaim:
			return "claim"
		default:
			return "other"
		}
	}(), "with the intent wiped the record authorizes a second presentation of the same token")

	assert.EqualValues(t, 1, after.GetEpoch(),
		"one login is one epoch; a lost acknowledgement must not look like a second login")
}

// TestSupersedeRepeatedCallIsIdempotent covers the layer above the one the test
// before it covers. The login flow retries Supersede itself when a write times
// out, which produces a second call, not a second flight: the epoch target lives
// inside one call and cannot help. If the first call did land, the second must
// still not clear an intent committed in between.
func TestSupersedeRepeatedCallIsIdempotent(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)

	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	client := dbtestutil.NewTestDatabroker(t)
	login := New(client, nil, WithNow(clk.Now))
	replica := New(client, newAuthGetter(auth), WithNow(clk.Now))

	id := RecordID("u", "i")
	require.NoError(t, login.Supersede(ctx, "u", "i", "rt-login", "id-token"))

	// A caller claims the intent on the new token and goes to the IdP, exactly
	// as one would while the login flow is deciding to retry.
	claimed, err := replica.claim(ctx, id, liveOptions{})
	require.NoError(t, err)
	require.Equal(t, outcomeClaimed, claimed.kind)
	require.NotEmpty(t, claimed.rec.GetRefreshAttemptId())

	// The login flow retries because it never saw the first write acknowledged.
	require.NoError(t, login.Supersede(ctx, "u", "i", "rt-login", "id-token"))

	after, err := replica.get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, claimed.rec.GetRefreshAttemptId(), after.GetRefreshAttemptId(),
		"a repeated call must not clear the intent of an attempt that is at the IdP")
	assert.EqualValues(t, 1, after.GetEpoch(),
		"one login is one epoch however many times the write is attempted")
	assert.NotEqual(t, outcomeClaim, replica.decide(after, liveOptions{}).kind,
		"with the intent wiped the record would authorize a second presentation")
}

// TestClaimRetryAfterLostAckAdoptsItsOwnIntent covers the other flight whose
// callback can run twice. The claim commits an intent, its acknowledgement is
// lost, and Store.do retries. The retry re-reads the record and finds an intent
// already there. If it read that as a foreign holder it would back off and wait
// out the settle window on an intent it owns itself, stranding every consumer of
// this user for three minutes over a databroker blip.
func TestClaimRetryAfterLostAckAdoptsItsOwnIntent(t *testing.T) {
	t.Parallel()
	ctx := testutil.GetContext(t, time.Minute)

	clk := &fakeClock{t: time.Now()}
	auth := &fakeAuth{lifetime: time.Hour, now: clk.Now}
	raw := dbtestutil.NewTestDatabroker(t)
	lossy := &lostAckClient{DataBrokerServiceClient: raw}

	seeder := New(raw, newAuthGetter(auth), WithNow(clk.Now))
	require.NoError(t, seeder.Register(ctx, "u", "i", "rt-1"))

	id := RecordID("u", "i")
	s := New(lossy, newAuthGetter(auth), WithNow(clk.Now))

	lost := make(chan struct{})
	lossy.onLostAck = func() { close(lost) }
	lossy.arm.Store(true)

	out, err := s.claim(ctx, id, liveOptions{})
	require.NoError(t, err, "a lost acknowledgement is not a failed claim")
	select {
	case <-lost:
	default:
		t.Fatal("the test did not exercise the lost-acknowledgement path")
	}

	require.Equal(t, outcomeClaimed, out.kind,
		"the caller whose intent is on the record is the one authorized to present")
	rec, err := seeder.get(ctx, id)
	require.NoError(t, err)
	assert.Equal(t, rec.GetRefreshAttemptId(), out.rec.GetRefreshAttemptId(),
		"the caller must be given the intent that is actually committed, or its commit fails the ownership check")
}
