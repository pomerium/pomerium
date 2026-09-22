package mcp

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

// listRoutesTestStorage is a minimal mock implementing only the methods
// called by checkHostsConnectedForUser.
type listRoutesTestStorage struct {
	HandlerStorage
	mcpTokens map[string]*oauth21proto.UpstreamMCPToken // key: userID|routeID|upstream
}

func (s *listRoutesTestStorage) GetUpstreamMCPToken(_ context.Context, userID, routeID, upstreamServer string) (*oauth21proto.UpstreamMCPToken, error) {
	key := userID + "|" + routeID + "|" + upstreamServer
	if tok, ok := s.mcpTokens[key]; ok {
		return tok, nil
	}
	return nil, status.Error(codes.NotFound, "not found")
}

func TestCheckHostsConnectedForUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		servers  []serverInfo
		storage  *listRoutesTestStorage
		wantConn []bool // expected Connected value per server
	}{
		{
			name: "no oauth needed marks connected",
			servers: []serverInfo{
				{host: "a.example.com", NeedsOauth: false},
			},
			storage:  &listRoutesTestStorage{},
			wantConn: []bool{true},
		},
		{
			name: "route with token is connected",
			servers: []serverInfo{
				{host: "a.example.com", NeedsOauth: true, routeID: "r1", upstreamURL: "https://upstream.example.com"},
			},
			storage: &listRoutesTestStorage{
				mcpTokens: map[string]*oauth21proto.UpstreamMCPToken{
					"user1|r1|https://upstream.example.com": {},
				},
			},
			wantConn: []bool{true},
		},
		{
			name: "route without token is not connected",
			servers: []serverInfo{
				{host: "a.example.com", NeedsOauth: true, routeID: "r1", upstreamURL: "https://upstream.example.com"},
			},
			storage:  &listRoutesTestStorage{},
			wantConn: []bool{false},
		},
		{
			name: "auto-discovery with valid token is connected",
			servers: []serverInfo{
				{host: "a.example.com", NeedsOauth: true, routeID: "r1", upstreamURL: "https://upstream.example.com"},
			},
			storage: &listRoutesTestStorage{
				mcpTokens: map[string]*oauth21proto.UpstreamMCPToken{
					"user1|r1|https://upstream.example.com": {
						ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
					},
				},
			},
			wantConn: []bool{true},
		},
		{
			name: "auto-discovery with nil expiry is connected",
			servers: []serverInfo{
				{host: "a.example.com", NeedsOauth: true, routeID: "r1", upstreamURL: "https://upstream.example.com"},
			},
			storage: &listRoutesTestStorage{
				mcpTokens: map[string]*oauth21proto.UpstreamMCPToken{
					"user1|r1|https://upstream.example.com": {
						ExpiresAt: nil,
					},
				},
			},
			wantConn: []bool{true},
		},
		{
			name: "auto-discovery with expired token is still connected (refresh handles it)",
			servers: []serverInfo{
				{host: "a.example.com", NeedsOauth: true, routeID: "r1", upstreamURL: "https://upstream.example.com"},
			},
			storage: &listRoutesTestStorage{
				mcpTokens: map[string]*oauth21proto.UpstreamMCPToken{
					"user1|r1|https://upstream.example.com": {
						ExpiresAt: timestamppb.New(time.Now().Add(-time.Hour)),
					},
				},
			},
			wantConn: []bool{true},
		},
		{
			name: "auto-discovery without token is not connected",
			servers: []serverInfo{
				{host: "a.example.com", NeedsOauth: true, routeID: "r1", upstreamURL: "https://upstream.example.com"},
			},
			storage:  &listRoutesTestStorage{},
			wantConn: []bool{false},
		},
		{
			name: "auto-discovery with missing routeID skips check",
			servers: []serverInfo{
				{host: "a.example.com", NeedsOauth: true, routeID: "", upstreamURL: "https://upstream.example.com"},
			},
			storage:  &listRoutesTestStorage{},
			wantConn: []bool{false},
		},
		{
			name: "mixed routes",
			servers: []serverInfo{
				{host: "static.example.com", NeedsOauth: true, routeID: "r1", upstreamURL: "https://upstream1.example.com"},
				{host: "auto.example.com", NeedsOauth: true, routeID: "r2", upstreamURL: "https://upstream2.example.com"},
				{host: "no-auth.example.com", NeedsOauth: false},
			},
			storage: &listRoutesTestStorage{
				mcpTokens: map[string]*oauth21proto.UpstreamMCPToken{
					"user1|r1|https://upstream1.example.com": {},
					"user1|r2|https://upstream2.example.com": {
						ExpiresAt: timestamppb.New(time.Now().Add(-time.Minute)),
					},
				},
			},
			wantConn: []bool{true, true, true},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := &Handler{storage: tc.storage}
			result, err := srv.checkHostsConnectedForUser(context.Background(), "user1", tc.servers)
			require.NoError(t, err)
			require.Len(t, result, len(tc.wantConn))
			for i, want := range tc.wantConn {
				assert.Equal(t, want, result[i].Connected, "server[%d] %s", i, result[i].host)
			}
		})
	}
}

// errUpstreamTokenStorage fails every lookup with a non-NotFound status, which
// is the one case IsUpstreamConnected must surface rather than answer.
type errUpstreamTokenStorage struct{ HandlerStorage }

func (*errUpstreamTokenStorage) GetUpstreamMCPToken(context.Context, string, string, string) (*oauth21proto.UpstreamMCPToken, error) {
	return nil, status.Error(codes.Unavailable, "databroker is down")
}

// TestIsUpstreamConnected covers the shared check directly, since both the
// routes portal and the agentic consent page now render their connection state
// from it and must not disagree.
func TestIsUpstreamConnected(t *testing.T) {
	t.Parallel()

	const (
		routeID  = "r1"
		upstream = "https://upstream.example.com"
	)
	storage := &listRoutesTestStorage{mcpTokens: map[string]*oauth21proto.UpstreamMCPToken{
		"user1|" + routeID + "|" + upstream: {ExpiresAt: timestamppb.New(time.Now().Add(-time.Hour))},
	}}

	t.Run("a stored token is connected even past its expiry", func(t *testing.T) {
		t.Parallel()
		connected, err := IsUpstreamConnected(context.Background(), storage, "user1", routeID, upstream)
		require.NoError(t, err)
		assert.True(t, connected, "the record carries a refresh token, so an expired access token is still a connection")
	})

	t.Run("no token is not connected, and not an error", func(t *testing.T) {
		t.Parallel()
		connected, err := IsUpstreamConnected(context.Background(), storage, "user2", routeID, upstream)
		require.NoError(t, err)
		assert.False(t, connected)
	})

	t.Run("nothing to connect to is not connected", func(t *testing.T) {
		t.Parallel()
		connected, err := IsUpstreamConnected(context.Background(), storage, "user1", "", upstream)
		require.NoError(t, err)
		assert.False(t, connected)

		connected, err = IsUpstreamConnected(context.Background(), storage, "user1", routeID, "")
		require.NoError(t, err)
		assert.False(t, connected)
	})

	t.Run("a transient lookup failure is an error, not a false", func(t *testing.T) {
		t.Parallel()
		_, err := IsUpstreamConnected(context.Background(), &errUpstreamTokenStorage{}, "user1", routeID, upstream)
		require.Error(t, err)
	})
}
