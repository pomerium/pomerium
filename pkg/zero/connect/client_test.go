package connect_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/zero/token"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
	"github.com/pomerium/pomerium/pkg/zero/connect"
)

func TestConfig(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		endpoint      string
		connectionURI string
		requireTLS    bool
		expectError   bool
	}{
		{"http://localhost:8721", "dns:localhost:8721", false, false},
		{"https://localhost:8721", "dns:localhost:8721", true, false},
		{"http://localhost:8721/", "dns:localhost:8721", false, false},
		{"https://localhost:8721/", "dns:localhost:8721", true, false},
		{"http://localhost", "dns:localhost:80", false, false},
		{"https://localhost", "dns:localhost:443", true, false},

		{endpoint: "", expectError: true},
		{endpoint: "http://", expectError: true},
		{endpoint: "https://", expectError: true},
		{endpoint: "localhost:8721", expectError: true},
		{endpoint: "http://localhost:8721/path", expectError: true},
		{endpoint: "https://localhost:8721/path", expectError: true},
	} {
		tc := tc
		t.Run(tc.endpoint, func(t *testing.T) {
			t.Parallel()
			cfg, err := connect.NewConfig(tc.endpoint)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			if assert.NoError(t, err) {
				assert.Equal(t, tc.connectionURI, cfg.GetConnectionURI(), "connection uri")
				assert.Equal(t, tc.requireTLS, cfg.RequireTLS(), "require tls")
			}
		})
	}
}

func TestConnectClient(t *testing.T) {
	refreshToken := os.Getenv("CONNECT_CLUSTER_IDENTITY_TOKEN")
	if refreshToken == "" {
		t.Skip("CONNECT_CLUSTER_IDENTITY_TOKEN not set")
	}

	connectServerEndpoint := os.Getenv("CONNECT_SERVER_ENDPOINT")
	if connectServerEndpoint == "" {
		connectServerEndpoint = "http://localhost:8721"
	}

	clusterAPIEndpoint := os.Getenv("CLUSTER_API_ENDPOINT")
	if clusterAPIEndpoint == "" {
		clusterAPIEndpoint = "http://localhost:8720/cluster/v1"
	}

	fetcher, err := cluster_api.NewTokenFetcher(clusterAPIEndpoint)
	require.NoError(t, err, "error creating token fetcher")

	ctx := context.Background()
	deadline, ok := t.Deadline()
	if ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, deadline.Add(-1*time.Second))
		t.Cleanup(cancel)
	}

	tokenCache := token.NewCache(fetcher, refreshToken)

	connectClient, err := connect.NewAuthorizedConnectClient(ctx, connectServerEndpoint, tokenCache.GetToken)
	require.NoError(t, err, "error creating connect client")

	stream, err := connectClient.Subscribe(ctx, &connect.SubscribeRequest{})
	require.NoError(t, err, "error subscribing")

	for {
		msg, err := stream.Recv()
		require.NoError(t, err, "error receiving message")
		t.Log(msg)
	}
}
