package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/mcp"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const (
	seededUpstreamToken = "seeded-upstream-access-token"
	seededRouteID       = "late-mcp-route"
	seededSAID          = "ext-proc-late-route-sa"
	seededSAUserID      = "late-route-user@example.com"
)

// TestExtProcUsesUpdatedDatabrokerConfigForLateMCPRoute documents a bug where
// the MCP ext_proc UpstreamAuthHandler does not pick up an MCP server route
// added after startup via the databroker config sync path that Pomerium Zero
// uses to deliver configuration.
//
// The handler wraps a *mcp.HostInfo whose map of hostname -> ServerHostInfo is
// materialized once behind a sync.Once the first time it is queried and never
// rebuilt. When a new route arrives via the databroker config syncer:
//
//   - xDS updates, so Envoy routes the new virtual host and ext_authz /
//     ext_proc filters run on the request.
//   - The ext_authz headers evaluator strips the Authorization header for
//     MCP server routes (the policy carries MCP.Server).
//   - ext_proc then calls UpstreamAuthHandler.GetUpstreamToken, which calls
//     HostInfo.GetServerHostInfo(hostname). Because the host map was frozen at
//     startup, this lookup returns (_, false), GetUpstreamToken returns empty,
//     no Authorization header is injected, and the upstream sees no credentials.
//
// Eventually is used only to wait for xDS to propagate the late-delivered
// route far enough that a request actually reaches the upstream. The RED
// assertion about token injection is a direct equality check — when the bug
// is fixed the test passes; on current main the upstream-side Authorization
// assertion fails cleanly, rather than the whole test timing out.
func TestExtProcUsesUpdatedDatabrokerConfigForLateMCPRoute(t *testing.T) {
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
	}))

	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: seededSAUserID}}))

	// Record the Authorization header the upstream actually receives. The
	// upstream returns 200 only when it sees the seeded Bearer token.
	var receivedAuth atomic.Pointer[string]
	listener := startBareUpstream(t, env.Host(), &receivedAuth)
	upstreamURL := "http://" + listener.Addr().String()

	env.Start()
	snippets.WaitStartupComplete(env)

	fromURL := env.SubdomainURL("mcp-late-route-test").Value()

	// Push the MCP route through the same databroker config delivery path
	// Pomerium Zero uses. env.NewDataBrokerServiceClient() keeps the transport
	// identical to Zero's outbound gRPC connection (shared JWT auth against
	// the outbound port).
	pushMCPRouteViaDatabroker(t, env, seededRouteID, fromURL, upstreamURL)

	ctx := env.Context()
	dbClient := env.NewDataBrokerServiceClient()

	sa := &user.ServiceAccount{Id: seededSAID, UserId: seededSAUserID}
	_, err := user.PutServiceAccount(ctx, dbClient, sa)
	require.NoError(t, err)

	saJWT, err := cryptutil.SignServiceAccount(
		env.SharedSecret(), sa.Id, sa.UserId, time.Now(), null.Time{},
	)
	require.NoError(t, err)

	// Seed the upstream MCP token under the same composite key ext_proc will
	// derive from (user_id, route_id, upstream_server).
	storage := mcp.NewStorage(dbClient)
	require.NoError(t, storage.PutUpstreamMCPToken(ctx, &oauth21proto.UpstreamMCPToken{
		UserId:         sa.UserId,
		RouteId:        seededRouteID,
		UpstreamServer: upstreamURL,
		AccessToken:    seededUpstreamToken,
		TokenType:      "Bearer",
	}))

	httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})

	makeRequest := func() int {
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, fromURL, nil)
		if err != nil {
			return 0
		}
		req.Header.Set("Authorization", "Bearer Pomerium-"+saJWT)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			return 0
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	// Split into phases so a timeout tells you which stage broke: xDS/ext_authz
	// (phase A) versus ext_proc HostInfo (phase B).
	var lastStatus int
	require.Eventuallyf(t, func() bool {
		lastStatus = makeRequest()
		return receivedAuth.Load() != nil
	}, 30*time.Second, 250*time.Millisecond,
		"late-delivered MCP route never reached the upstream (last status=%d); "+
			"likely xDS did not propagate the route or ext_authz blocked it", lastStatus)

	wantAuth := "Bearer " + seededUpstreamToken
	require.Eventuallyf(t, func() bool {
		lastStatus = makeRequest()
		p := receivedAuth.Load()
		return p != nil && *p == wantAuth
	}, 5*time.Second, 250*time.Millisecond,
		"upstream saw Authorization=%q (want %q), status=%d — "+
			"ext_proc did not inject the seeded upstream token",
		func() string {
			if p := receivedAuth.Load(); p != nil {
				return *p
			}
			return ""
		}(), wantAuth, lastStatus)

	assert.Equal(t, http.StatusOK, lastStatus,
		"request through Pomerium should succeed when upstream token is injected")
}

// startBareUpstream starts a minimal HTTP server on host:0 that writes the
// observed Authorization header through receivedAuth. It deliberately bypasses
// testenv's upstream/modifier path so the route only exists once we push it
// through the databroker.
func startBareUpstream(t *testing.T, host string, receivedAuth *atomic.Pointer[string]) net.Listener {
	t.Helper()

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", host))
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		receivedAuth.Store(&auth)
		if auth != "Bearer "+seededUpstreamToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	})
	return listener
}

// pushMCPRouteViaDatabroker creates a databroker client using the environment's
// outbound port + shared secret (the same transport Zero uses) and writes a
// configpb.Config record containing a single MCP server route. The config
// syncer inside the running pomerium process picks the record up and folds the
// route into the live configuration, which propagates to Envoy via xDS.
func pushMCPRouteViaDatabroker(t *testing.T, env testenv.Environment, routeID, fromURL, toURL string) {
	t.Helper()

	dbClient := env.NewDataBrokerServiceClient()

	idPtr := routeID
	namePtr := routeID
	route := &configpb.Route{
		Id:                        &idPtr,
		Name:                      &namePtr,
		From:                      fromURL,
		To:                        []string{toURL},
		AllowAnyAuthenticatedUser: true,
		Mcp: &configpb.MCP{
			Mode: &configpb.MCP_Server{
				Server: &configpb.MCPServer{},
			},
		},
	}
	data := protoutil.NewAny(&configpb.Config{
		Name:   "late-mcp-route-config",
		Routes: []*configpb.Route{route},
	})

	ctx, cancel := context.WithTimeout(env.Context(), 10*time.Second)
	defer cancel()

	_, err := dbClient.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Id:   "late-mcp-route-config",
			Type: data.TypeUrl,
			Data: data,
		}},
	})
	require.NoError(t, err, "failed to push MCP route config via databroker")
}
