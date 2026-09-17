package mcp

import (
	"context"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/databroker"
	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

var syncerTestBase = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

func TestStorageSyncerClearRecords(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)
	client := newTestDataBrokerClient(t)
	s := newTestStorageSyncer(t, client, &fakeClock{t: syncerTestBase})
	s.records["a"] = &RefreshTokenMd{}

	s.ClearRecords(ctx)

	assert.Empty(t, s.records)
}

func TestStorageSyncerCleanUp(t *testing.T) {
	t.Parallel()

	const grace = time.Hour

	type testToken struct {
		id string
		// expiresIn is the token lifetime relative to the start of the test
		expiresIn *time.Duration
		revoked   bool
	}

	dur := func(d time.Duration) *time.Duration { return new(d) }

	type testcase struct {
		name string
		// tokens are all created at the start of the test.
		tokens []testToken
		// advance is how far the clock moves before cleanup runs.
		advance       time.Duration
		wantRemaining []string
	}

	for _, tc := range []testcase{
		{
			name: "no tokens is a no-op",
		},
		{
			name:          "unexpired token is kept",
			tokens:        []testToken{{id: "a", expiresIn: dur(4 * time.Hour)}},
			advance:       time.Hour,
			wantRemaining: []string{"a"},
		},
		{
			name:    "token without an expiry is treated as already expired",
			tokens:  []testToken{{id: "a"}},
			advance: time.Minute,
		},
		{
			name:          "expired token within the grace period is kept",
			tokens:        []testToken{{id: "a", expiresIn: dur(time.Hour)}},
			advance:       time.Hour + 30*time.Minute,
			wantRemaining: []string{"a"},
		},
		{
			name:    "expired token past the grace period is deleted",
			tokens:  []testToken{{id: "a", expiresIn: dur(time.Hour)}},
			advance: 3 * time.Hour,
		},
		{
			name:          "expired token exactly at the grace boundary is kept",
			tokens:        []testToken{{id: "a", expiresIn: dur(time.Hour)}},
			advance:       time.Hour + grace,
			wantRemaining: []string{"a"},
		},
		{
			name:          "revoked token within the grace period is kept",
			tokens:        []testToken{{id: "a", expiresIn: dur(100 * time.Hour), revoked: true}},
			advance:       30 * time.Minute,
			wantRemaining: []string{"a"},
		},
		{
			name:    "revoked token past the grace period is deleted",
			tokens:  []testToken{{id: "a", expiresIn: dur(100 * time.Hour), revoked: true}},
			advance: 2 * time.Hour,
		},
		{
			name: "only eligible tokens are deleted",
			tokens: []testToken{
				{id: "revoked", expiresIn: dur(100 * time.Hour), revoked: true},
				{id: "expired", expiresIn: dur(time.Minute)},
				{id: "still-valid", expiresIn: dur(100 * time.Hour)},
				{id: "no-expiry"},
			},
			advance:       2 * time.Hour,
			wantRemaining: []string{"still-valid"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.GetContext(t, time.Minute)
			client := newTestDataBrokerClient(t)
			storage := NewStorage(client)
			clock := &fakeClock{t: syncerTestBase}
			s := newTestStorageSyncer(t, client, clock, WithCleanupGracePeriod(grace),
				WithCleanupInterval(10*time.Millisecond))

			tracked := func() []string {
				s.mu.RLock()
				defer s.mu.RUnlock()
				return slices.Collect(maps.Keys(s.records))
			}

			var ids []string
			for _, tok := range tc.tokens {
				stored := &oauth21.MCPRefreshToken{Id: tok.id, Revoked: tok.revoked}
				if tok.expiresIn != nil {
					stored.ExpiresAt = timestamppb.New(syncerTestBase.Add(*tok.expiresIn))
				}
				require.NoError(t, storage.PutMCPRefreshToken(ctx, stored))
				ids = append(ids, tok.id)
			}

			syncer := databrokerutil.NewSyncer(ctx, "mcp-refresh-token-test", s,
				databrokerutil.WithTypeURL(protoutil.GetTypeURL(new(oauth21.MCPRefreshToken))))
			t.Cleanup(func() { _ = syncer.Close() })
			go func() { _ = syncer.Run(ctx) }()

			// Wait for the initial sync so every token is tracked before the clock moves.
			require.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.ElementsMatch(c, ids, tracked())
			}, 5*time.Second, 10*time.Millisecond, "initial sync never completed")

			clock.Set(syncerTestBase.Add(tc.advance))
			go func() { _ = s.RunCleanUp(ctx) }()

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				var remaining []string
				for _, tok := range tc.tokens {
					if _, err := storage.GetMCPRefreshToken(ctx, tok.id); err == nil {
						remaining = append(remaining, tok.id)
					}
				}
				assert.ElementsMatch(c, tc.wantRemaining, remaining,
					"unexpected set of tokens left in the databroker")
				assert.ElementsMatch(c, tc.wantRemaining, tracked(),
					"in-memory tracking diverged from the databroker")
			}, 5*time.Second, 10*time.Millisecond)
		})
	}
}

func TestStorageSyncerRunCleanUpStopsOnContextCancel(t *testing.T) {
	t.Parallel()

	client := newTestDataBrokerClient(t)
	s := newTestStorageSyncer(t, client, &fakeClock{t: syncerTestBase})
	s.cleanupInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.ErrorIs(t, s.RunCleanUp(ctx), context.Canceled)
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func newTestDataBrokerClient(t *testing.T) databrokerpb.DataBrokerServiceClient {
	t.Helper()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})

	return databrokerpb.NewDataBrokerServiceClient(cc)
}

func newTestStorageSyncer(
	t *testing.T,
	client databrokerpb.DataBrokerServiceClient,
	clock *fakeClock,
	opts ...StorageSyncerOption,
) *StorageSyncer {
	t.Helper()

	return NewStorageSyncer(
		databrokerpb.NewStaticClientGetter(client),
		append([]StorageSyncerOption{WithClock(clock.Now)}, opts...)...,
	)
}
