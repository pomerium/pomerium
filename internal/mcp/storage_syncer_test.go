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
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

var syncerTestBase = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)

func TestTokenExpirationSyncerClearRecords(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)
	client := newTestDataBrokerClient(t)
	s := newTestTokenExpirationSyncer(t, client, &fakeClock{t: syncerTestBase})
	s.records["a"] = &RefreshTokenMd{}

	s.ClearRecords(ctx)

	assert.Empty(t, s.records)
}

func TestTokenExpirationSyncerCleanUp(t *testing.T) {
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
			s := newTestTokenExpirationSyncer(t, client, clock, WithCleanupGracePeriod(grace),
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

func TestTokenExpirationSyncerRunCleanUpStopsOnContextCancel(t *testing.T) {
	t.Parallel()

	client := newTestDataBrokerClient(t)
	s := newTestTokenExpirationSyncer(t, client, &fakeClock{t: syncerTestBase})
	s.cleanupInterval = time.Hour

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	require.ErrorIs(t, s.RunCleanUp(ctx), context.Canceled)
}

func TestMostRecentUsableRefreshToken(t *testing.T) {
	t.Parallel()

	type testRecord struct {
		id string
		// modifiedIn is the record's modification time relative to the start of the test
		modifiedIn time.Duration
		// expiresIn is the token lifetime relative to the start of the test
		expiresIn *time.Duration
		revoked   bool
		deleted   bool
	}

	dur := func(d time.Duration) *time.Duration { return &d }

	type testcase struct {
		name    string
		records []testRecord
		// wantID is the id of the expected token, empty means nil.
		wantID  string
		wantErr error
	}

	for _, tc := range []testcase{
		{
			name:    "single valid token",
			records: []testRecord{{id: "a", expiresIn: dur(time.Hour)}},
			wantID:  "a",
		},
		{
			name: "most recently modified valid token wins",
			records: []testRecord{
				{id: "old", modifiedIn: -2 * time.Hour, expiresIn: dur(time.Hour)},
				{id: "new", modifiedIn: -time.Minute, expiresIn: dur(time.Hour)},
				{id: "middle", modifiedIn: -time.Hour, expiresIn: dur(time.Hour)},
			},
			wantID: "new",
		},
		{
			name: "a newer unusable token does not beat an older valid one",
			records: []testRecord{
				{id: "valid", modifiedIn: -time.Hour, expiresIn: dur(time.Hour)},
				{id: "revoked", modifiedIn: -time.Minute, expiresIn: dur(time.Hour), revoked: true},
				{id: "expired", modifiedIn: -time.Second, expiresIn: dur(-time.Minute)},
			},
			wantID: "valid",
		},
		{
			name: "falls back to the most recently modified when none are usable",
			records: []testRecord{
				{id: "revoked", modifiedIn: -time.Hour, expiresIn: dur(time.Hour), revoked: true},
				{id: "expired", modifiedIn: -time.Minute, expiresIn: dur(-time.Minute)},
			},
			wantID: "expired",
		},
		{
			name:    "token without an expiry is not usable",
			records: []testRecord{{id: "a"}},
			wantID:  "a",
		},
		{
			name: "deleted records are ignored",
			records: []testRecord{
				{id: "deleted", modifiedIn: -time.Minute, expiresIn: dur(time.Hour), deleted: true},
				{id: "a", modifiedIn: -time.Hour, expiresIn: dur(time.Hour)},
			},
			wantID: "a",
		},
		{
			name:    "all records deleted",
			records: []testRecord{{id: "a", expiresIn: dur(time.Hour), deleted: true}},
			wantErr: ErrNoMCPToken,
		},
		{
			name: "token expiring exactly now is not usable",
			records: []testRecord{
				{id: "boundary", modifiedIn: -time.Minute, expiresIn: dur(0)},
				{id: "valid", modifiedIn: -time.Hour, expiresIn: dur(time.Hour)},
			},
			wantID: "valid",
		},
		{
			name: "all tokens revoked or expired falls back to the newest",
			records: []testRecord{
				{id: "revoked-old", modifiedIn: -3 * time.Hour, expiresIn: dur(time.Hour), revoked: true},
				{id: "expired-newest", modifiedIn: -time.Minute, expiresIn: dur(-time.Hour)},
				{id: "no-expiry", modifiedIn: -2 * time.Hour},
				{id: "revoked-and-expired", modifiedIn: -time.Hour, expiresIn: dur(-time.Minute), revoked: true},
			},
			wantID: "expired-newest",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.GetContext(t, time.Minute)

			var records []*databrokerpb.Record
			for _, r := range tc.records {
				token := &oauth21.MCPRefreshToken{Id: r.id, Revoked: r.revoked}
				if r.expiresIn != nil {
					token.ExpiresAt = timestamppb.New(syncerTestBase.Add(*r.expiresIn))
				}
				rec := &databrokerpb.Record{
					Id:         r.id,
					Data:       protoutil.NewAny(token),
					ModifiedAt: timestamppb.New(syncerTestBase.Add(r.modifiedIn)),
				}
				if r.deleted {
					rec.DeletedAt = timestamppb.New(syncerTestBase)
				}
				records = append(records, rec)
			}

			got, err := mostRecentUsableRefreshToken(ctx, records, syncerTestBase)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr, tc.name)
				assert.Nil(t, got, tc.name)
				return
			}
			require.NoError(t, err, tc.name)
			require.NotNil(t, got, tc.name)
			assert.Equal(t, tc.wantID, got.GetId(), tc.name)
		})
	}
}

func TestSessionTokenSyncer(t *testing.T) {
	t.Parallel()

	type testSession struct {
		id              string
		accessToken     string
		refreshToken    string
		expiresIn       *time.Duration
		refreshDisabled bool
		deleted         bool
	}

	type testToken struct {
		id                   string
		initiatingSessionID  string
		upstreamRefreshToken string
		// expiresIn is the token lifetime relative to now
		expiresIn *time.Duration
		revoked   bool
	}

	dur := func(d time.Duration) *time.Duration { return &d }

	type testcase struct {
		name     string
		sessions []testSession
		tokens   []testToken
		// wantUpstream maps a token id to the upstream refresh token it should end up with.
		wantUpstream map[string]string
	}

	for _, tc := range []testcase{
		{
			name: "stale upstream refresh token is updated from the session",
			sessions: []testSession{
				{id: "s1", accessToken: "at", refreshToken: "new-upstream", expiresIn: dur(time.Hour)},
			},
			tokens: []testToken{
				{id: "t1", initiatingSessionID: "s1", upstreamRefreshToken: "old-upstream", expiresIn: dur(time.Hour)},
			},
			wantUpstream: map[string]string{"t1": "new-upstream"},
		},
		{
			name: "only the token for the matching session is updated",
			sessions: []testSession{
				{id: "s1", accessToken: "at", refreshToken: "new-upstream", expiresIn: dur(time.Hour)},
			},
			tokens: []testToken{
				{id: "t1", initiatingSessionID: "s1", upstreamRefreshToken: "old-upstream", expiresIn: dur(time.Hour)},
				{id: "t2", initiatingSessionID: "other", upstreamRefreshToken: "untouched", expiresIn: dur(time.Hour)},
			},
			wantUpstream: map[string]string{"t1": "new-upstream", "t2": "untouched"},
		},
		{
			name: "the most recently written usable token for the session is updated",
			sessions: []testSession{
				{id: "s1", accessToken: "at", refreshToken: "new-upstream", expiresIn: dur(time.Hour)},
			},
			tokens: []testToken{
				{id: "expired", initiatingSessionID: "s1", upstreamRefreshToken: "stale-expired", expiresIn: dur(-time.Hour)},
				{id: "revoked", initiatingSessionID: "s1", upstreamRefreshToken: "stale-revoked", expiresIn: dur(time.Hour), revoked: true},
				{id: "valid", initiatingSessionID: "s1", upstreamRefreshToken: "old-upstream", expiresIn: dur(time.Hour)},
			},
			wantUpstream: map[string]string{
				"expired": "stale-expired",
				"revoked": "stale-revoked",
				"valid":   "new-upstream",
			},
		},
		{
			// The identity manager's last refresh lands after the session has expired, and it is
			// the one that rotates the upstream token at the IdP, so it must still propagate.
			name: "expired session still propagates its upstream refresh token",
			sessions: []testSession{
				{id: "s1", accessToken: "at", refreshToken: "new-upstream", expiresIn: dur(-time.Hour)},
			},
			tokens: []testToken{
				{id: "t1", initiatingSessionID: "s1", upstreamRefreshToken: "old-upstream", expiresIn: dur(time.Hour)},
			},
			wantUpstream: map[string]string{"t1": "new-upstream"},
		},
		{
			name: "session with refresh disabled still propagates its upstream refresh token",
			sessions: []testSession{
				{id: "s1", accessToken: "at", refreshToken: "new-upstream", expiresIn: dur(time.Hour), refreshDisabled: true},
			},
			tokens: []testToken{
				{id: "t1", initiatingSessionID: "s1", upstreamRefreshToken: "old-upstream", expiresIn: dur(time.Hour)},
			},
			wantUpstream: map[string]string{"t1": "new-upstream"},
		},
		{
			name: "session without an upstream refresh token is skipped",
			sessions: []testSession{
				{id: "s1", accessToken: "at", expiresIn: dur(time.Hour)},
			},
			tokens: []testToken{
				{id: "t1", initiatingSessionID: "s1", upstreamRefreshToken: "old-upstream", expiresIn: dur(time.Hour)},
			},
			wantUpstream: map[string]string{"t1": "old-upstream"},
		},
		{
			name: "a deleted session does not blank the stored upstream refresh token",
			sessions: []testSession{
				{id: "s1", accessToken: "at", refreshToken: "new-upstream", expiresIn: dur(time.Hour), deleted: true},
			},
			tokens: []testToken{
				{id: "t1", initiatingSessionID: "s1", upstreamRefreshToken: "old-upstream", expiresIn: dur(time.Hour)},
			},
			wantUpstream: map[string]string{"t1": "old-upstream"},
		},
		{
			name: "session without a matching token is a no-op",
			sessions: []testSession{
				{id: "s1", accessToken: "at", refreshToken: "new-upstream", expiresIn: dur(time.Hour)},
			},
			tokens: []testToken{
				{id: "t1", initiatingSessionID: "other", upstreamRefreshToken: "untouched", expiresIn: dur(time.Hour)},
			},
			wantUpstream: map[string]string{"t1": "untouched"},
		},
		{
			name: "an already matching token is left alone",
			sessions: []testSession{
				{id: "s1", accessToken: "at", refreshToken: "same-upstream", expiresIn: dur(time.Hour)},
			},
			tokens: []testToken{
				{id: "t1", initiatingSessionID: "s1", upstreamRefreshToken: "same-upstream", expiresIn: dur(time.Hour)},
			},
			wantUpstream: map[string]string{"t1": "same-upstream"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.GetContext(t, time.Minute)
			client := newTestDataBrokerClient(t)
			storage := NewStorage(client)
			now := time.Now()

			for _, tok := range tc.tokens {
				stored := &oauth21.MCPRefreshToken{
					Id:                   tok.id,
					InitiatingSessionId:  tok.initiatingSessionID,
					UpstreamRefreshToken: tok.upstreamRefreshToken,
					Revoked:              tok.revoked,
				}
				if tok.expiresIn != nil {
					stored.ExpiresAt = timestamppb.New(now.Add(*tok.expiresIn))
				}
				require.NoError(t, storage.PutMCPRefreshToken(ctx, stored))
			}

			for _, sess := range tc.sessions {
				stored := &session.Session{
					Id:              sess.id,
					UserId:          "user-" + sess.id,
					RefreshDisabled: sess.refreshDisabled,
					OauthToken: &session.OAuthToken{
						AccessToken:  sess.accessToken,
						RefreshToken: sess.refreshToken,
					},
				}
				if sess.expiresIn != nil {
					stored.ExpiresAt = timestamppb.New(now.Add(*sess.expiresIn))
				}
				rec := databrokerpb.NewRecord(stored)
				if sess.deleted {
					rec.DeletedAt = timestamppb.New(now)
				}
				_, err := client.Put(ctx, &databrokerpb.PutRequest{Records: []*databrokerpb.Record{rec}})
				require.NoError(t, err)
			}

			s := newSessionTokenSyncer(databrokerpb.NewStaticClientGetter(client))
			syncer := databrokerutil.NewSyncer(ctx, "mcp-session-token-test", s,
				databrokerutil.WithTypeURL(protoutil.GetTypeURL(new(session.Session))))
			t.Cleanup(func() { _ = syncer.Close() })
			go func() { _ = syncer.Run(ctx) }()

			upstream := func() map[string]string {
				got := map[string]string{}
				for _, tok := range tc.tokens {
					stored, err := storage.GetMCPRefreshToken(ctx, tok.id)
					if err != nil {
						continue
					}
					got[tok.id] = stored.GetUpstreamRefreshToken()
				}
				return got
			}

			initial := map[string]string{}
			for _, tok := range tc.tokens {
				initial[tok.id] = tok.upstreamRefreshToken
			}

			// When the syncer is expected to leave everything as stored, waiting for the
			// expectation to hold proves nothing: assert it never stops holding instead.
			if assert.ObjectsAreEqual(tc.wantUpstream, initial) {
				assert.Never(t, func() bool {
					return !assert.ObjectsAreEqual(tc.wantUpstream, upstream())
				}, time.Second, 50*time.Millisecond,
					"the syncer modified a token it should have left alone")
				return
			}

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				assert.Equal(c, tc.wantUpstream, upstream())
			}, 5*time.Second, 10*time.Millisecond)
		})
	}
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

func newTestTokenExpirationSyncer(
	t *testing.T,
	client databrokerpb.DataBrokerServiceClient,
	clock *fakeClock,
	opts ...TokenExpirationSyncerOption,
) *tokenExpirationSyncer {
	t.Helper()

	return newTokenExpirationSyncer(
		databrokerpb.NewStaticClientGetter(client),
		append([]TokenExpirationSyncerOption{WithClock(clock.Now)}, opts...)...,
	)
}
