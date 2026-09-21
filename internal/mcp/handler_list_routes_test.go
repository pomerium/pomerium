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

func TestCheckHostsConnectedForUserTokenDetails(t *testing.T) {
	t.Parallel()

	accessExpiry := time.Now().Add(42 * time.Minute).UTC().Truncate(time.Second)
	refreshExpiry := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)

	server := func() serverInfo {
		return serverInfo{host: "a.example.com", NeedsOauth: true, routeID: "r1", upstreamURL: "https://upstream.example.com"}
	}
	const tokenKey = "user1|r1|https://upstream.example.com"

	tests := []struct {
		name                      string
		token                     *oauth21proto.UpstreamMCPToken
		wantTokenExpiresAt        string
		wantRefreshAvailable      bool
		wantRefreshTokenExpiresAt string
	}{
		{
			name:  "no token",
			token: nil,
		},
		{
			name: "access token expiry and refresh token",
			token: &oauth21proto.UpstreamMCPToken{
				ExpiresAt:        timestamppb.New(accessExpiry),
				RefreshToken:     "rt",
				RefreshExpiresAt: timestamppb.New(refreshExpiry),
			},
			wantTokenExpiresAt:        accessExpiry.Format(time.RFC3339),
			wantRefreshAvailable:      true,
			wantRefreshTokenExpiresAt: refreshExpiry.Format(time.RFC3339),
		},
		{
			name: "no expiry, refresh token without expiry",
			token: &oauth21proto.UpstreamMCPToken{
				RefreshToken: "rt",
			},
			wantRefreshAvailable: true,
		},
		{
			name: "expiry without refresh token",
			token: &oauth21proto.UpstreamMCPToken{
				ExpiresAt: timestamppb.New(accessExpiry),
			},
			wantTokenExpiresAt: accessExpiry.Format(time.RFC3339),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			storage := &listRoutesTestStorage{mcpTokens: map[string]*oauth21proto.UpstreamMCPToken{}}
			if tc.token != nil {
				storage.mcpTokens[tokenKey] = tc.token
			}
			srv := &Handler{storage: storage}
			result, err := srv.checkHostsConnectedForUser(context.Background(), "user1", []serverInfo{server()})
			require.NoError(t, err)
			require.Len(t, result, 1)
			assert.Equal(t, tc.token != nil, result[0].Connected)
			assert.Equal(t, tc.wantTokenExpiresAt, result[0].TokenExpiresAt)
			assert.Equal(t, tc.wantRefreshAvailable, result[0].RefreshTokenAvailable)
			assert.Equal(t, tc.wantRefreshTokenExpiresAt, result[0].RefreshTokenExpiresAt)
		})
	}
}

func TestGetPortalInfoForUser(t *testing.T) {
	t.Parallel()

	accessExpiry := time.Now().Add(15 * time.Minute).UTC().Truncate(time.Second)
	refreshExpiry := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Second)

	srv := &Handler{
		storage: &listRoutesTestStorage{
			mcpTokens: map[string]*oauth21proto.UpstreamMCPToken{
				"user1|r1|https://upstream.example.com": {
					ExpiresAt:        timestamppb.New(accessExpiry),
					RefreshToken:     "rt",
					RefreshExpiresAt: timestamppb.New(refreshExpiry),
				},
			},
		},
		hosts: newHostInfoForTest(map[string]ServerHostInfo{
			"a.example.com": {
				Host:        "a.example.com",
				URL:         "https://a.example.com",
				RouteID:     "r1",
				UpstreamURL: "https://upstream.example.com",
			},
		}, nil),
	}

	infos, err := srv.GetPortalInfoForUser(context.Background(), "user1")
	require.NoError(t, err)
	require.Len(t, infos, 1)
	assert.Equal(t, "a.example.com", infos[0].Host)
	assert.True(t, infos[0].Connected)
	assert.Equal(t, accessExpiry.Format(time.RFC3339), infos[0].TokenExpiresAt)
	assert.True(t, infos[0].RefreshTokenAvailable)
	assert.Equal(t, refreshExpiry.Format(time.RFC3339), infos[0].RefreshTokenExpiresAt)
}
