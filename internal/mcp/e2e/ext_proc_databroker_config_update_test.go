package e2e

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
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

// TestExtProcUsesUpdatedDatabrokerConfigForLateMCPRoute documents a bug where
// the MCP ext_proc UpstreamAuthHandler does not pick up an MCP server route
// added after startup via the databroker config sync path that Pomerium Zero
// uses to deliver configuration.
//
// The handler wraps a *mcp.HostInfo whose map of hostname -> ServerHostInfo is
// materialized once behind a sync.Once the first time it is queried, and never
// rebuilt. When a new route arrives via the databroker config syncer:
//
//   - xDS updates, so Envoy routes the new virtual host and ext_authz /
//     ext_proc filters run on the request.
//   - The ext_authz headers evaluator still strips the Authorization header for
//     MCP server routes (the policy carries MCP.Server).
//   - ext_proc then calls UpstreamAuthHandler.GetUpstreamToken, which calls
//     HostInfo.GetServerHostInfo(hostname). Because the host map was frozen at
//     startup, this lookup returns (_, false), GetUpstreamToken returns empty,
//     no Authorization header is injected, and the upstream sees no credentials.
//
// The control subtest configures the same MCP route at startup and proves the
// service-account auth + seeded UpstreamMCPToken + ext_proc path all work end
// to end. The primary subtest performs the identical seeding but pushes the
// route in via databroker after startup; on current main it fails because the
// upstream never receives the seeded Bearer token.
func TestExtProcUsesUpdatedDatabrokerConfigForLateMCPRoute(t *testing.T) {
	// Subtest names are kept short on purpose: envoy's admin Unix socket path
	// must fit in 108 bytes and this top-level test name already consumes 55.
	t.Run("start", func(t *testing.T) {
		runSeededSAMCPRoute(t, routeDeliveryStartup)
	})
	t.Run("late", func(t *testing.T) {
		runSeededSAMCPRoute(t, routeDeliveryLateDatabroker)
	})
}

type routeDelivery int

const (
	routeDeliveryStartup routeDelivery = iota
	routeDeliveryLateDatabroker
)

const (
	seededUpstreamToken = "seeded-upstream-access-token"
	seededRouteID       = "late-mcp-route"
	seededSAID          = "ext-proc-late-route-sa"
	seededSAUserID      = "late-route-user@example.com"
)

// runSeededSAMCPRoute exercises the full ext_proc + service-account + seeded
// UpstreamMCPToken path for a single MCP server route. The route is either
// configured at startup or pushed through the databroker config syncer after
// startup, depending on `delivery`. In both cases the test asserts that the
// upstream receives exactly "Bearer <seededUpstreamToken>".
func runSeededSAMCPRoute(t *testing.T, delivery routeDelivery) {
	t.Helper()

	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
	}))

	idp := scenarios.NewIDP([]*scenarios.User{
		{Email: seededSAUserID},
	})
	env.Add(idp)

	// Record the Authorization header the upstream actually receives. The
	// upstream returns 200 only when it sees the seeded Bearer token, so an
	// HTTP 401 reliably indicates token injection did not happen.
	var (
		receivedAuth atomic.Pointer[string]
		upstreamURL  string
	)

	switch delivery {
	case routeDeliveryStartup:
		serverUpstream := upstreams.HTTP(nil, upstreams.WithDisplayName("Startup MCP Server"))
		serverUpstream.Handle("/", func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			receivedAuth.Store(&auth)
			if auth != "Bearer "+seededUpstreamToken {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
		})
		serverRoute := serverUpstream.Route().
			From(env.SubdomainURL("mcp-late-route-test")).
			Policy(func(p *config.Policy) {
				// Fixed ID so we can seed the UpstreamMCPToken by the same key
				// the handler derives via Policy.RouteID().
				p.ID = seededRouteID
				p.AllowAnyAuthenticatedUser = true
				p.MCP = &config.MCP{
					Server: &config.MCPServer{},
				}
			})
		env.AddUpstream(serverUpstream)

		env.Start()
		snippets.WaitStartupComplete(env)

		// Resolve the concrete upstream URL only after startup, once testenv
		// has allocated the upstream's listening port. upstreams.HTTP.Route()
		// sets To = "http://<env.Host()>:<serverPort>", matching the format
		// that NewServerHostInfoFromPolicy uses to derive UpstreamURL.
		upstreamURL = "http://" + serverUpstream.Addr().Value()

		seedSATokenAndRun(t, env, seededRouteID, upstreamURL, serverRoute.URL().Value(), &receivedAuth)

	case routeDeliveryLateDatabroker:
		// Stand up an unmanaged HTTP listener for the late-delivered route.
		// We deliberately bypass testenv's upstream/modifier path so the
		// route only exists once we push it through the databroker.
		listener, handlerReady := startBareUpstream(t, env.Host(), &receivedAuth)
		upstreamURL = "http://" + listener.Addr().String()

		env.Start()
		snippets.WaitStartupComplete(env)

		// Wait until the bare upstream is actually accepting connections so
		// later polling isn't racing server startup.
		<-handlerReady

		fromURL := env.SubdomainURL("mcp-late-route-test").Value()

		// Push the MCP route through the same databroker config delivery path
		// Pomerium Zero uses. Using env.NewDataBrokerServiceClient() keeps the
		// transport identical to Zero's outbound gRPC connection (shared JWT
		// auth against the outbound port).
		pushMCPRouteViaDatabroker(t, env, seededRouteID, fromURL, upstreamURL)

		seedSATokenAndRun(t, env, seededRouteID, upstreamURL, fromURL, &receivedAuth)

	default:
		t.Fatalf("unknown delivery mode %v", delivery)
	}
}

// startBareUpstream starts a minimal HTTP server on host:0 that writes the
// observed Authorization header through receivedAuth. It returns the listener
// and a channel that closes as soon as the server is serving, so callers can
// wait on startup deterministically.
func startBareUpstream(t *testing.T, host string, receivedAuth *atomic.Pointer[string]) (net.Listener, <-chan struct{}) {
	t.Helper()

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", host))
	require.NoError(t, err)

	ready := make(chan struct{})
	var once sync.Once

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		receivedAuth.Store(&auth)
		once.Do(func() { close(ready) })
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

	// Flip `ready` as soon as the listener is bound; the request handler will
	// also close it on the first observed request, whichever happens first.
	once.Do(func() { close(ready) })
	return listener, ready
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

// seedSATokenAndRun provisions a service account and a matching UpstreamMCPToken
// record, then polls the MCP route through Envoy with the SA JWT until it
// either gets an HTTP 200 with the expected injected Authorization header or
// times out. The polling window is long enough to absorb xDS propagation for
// the late-delivery case; on current main the late-delivery run times out
// because the upstream keeps seeing no Authorization.
func seedSATokenAndRun(
	t *testing.T,
	env testenv.Environment,
	routeID, upstreamURL, fromURL string,
	receivedAuth *atomic.Pointer[string],
) {
	t.Helper()

	ctx := env.Context()
	dbClient := env.NewDataBrokerServiceClient()

	sa := &user.ServiceAccount{
		Id:     seededSAID,
		UserId: seededSAUserID,
	}
	_, err := user.PutServiceAccount(ctx, dbClient, sa)
	require.NoError(t, err)

	saJWT, err := cryptutil.SignServiceAccount(
		env.SharedSecret(),
		sa.Id,
		sa.UserId,
		time.Now(),
		null.Time{},
	)
	require.NoError(t, err)

	// Seed the upstream MCP token under the same composite key ext_proc will
	// derive from (user_id, route_id, upstream_server).
	storage := mcp.NewStorage(dbClient)
	require.NoError(t, storage.PutUpstreamMCPToken(ctx, &oauth21proto.UpstreamMCPToken{
		UserId:         sa.UserId,
		RouteId:        routeID,
		UpstreamServer: upstreamURL,
		AccessToken:    seededUpstreamToken,
		TokenType:      "Bearer",
	}))

	httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})

	makeRequest := func() (int, string) {
		reqCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, fromURL, nil)
		if err != nil {
			return 0, ""
		}
		req.Header.Set("Authorization", "Bearer Pomerium-"+saJWT)
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpClient.Do(req)
		if err != nil {
			return 0, ""
		}
		defer resp.Body.Close()
		got := ""
		if p := receivedAuth.Load(); p != nil {
			got = *p
		}
		return resp.StatusCode, got
	}

	// The route + seeded token must result in HTTP 200 and the upstream must
	// see the injected Bearer token. Eventually absorbs both xDS propagation
	// and databroker-syncer timing; on current main it times out in the
	// late-delivery case because ext_proc never injects the token.
	var (
		lastStatus int
		lastAuth   string
	)
	require.Eventually(t, func() bool {
		status, auth := makeRequest()
		lastStatus, lastAuth = status, auth
		return status == http.StatusOK && auth == "Bearer "+seededUpstreamToken
	}, 30*time.Second, 250*time.Millisecond,
		"expected ext_proc to inject the seeded upstream token for route %q (last status=%d, last upstream Authorization=%q)",
		routeID, lastStatus, lastAuth)

	// Re-assert the final state explicitly so the failure message names the
	// two distinct expectations (HTTP 200 + correct injected Bearer header).
	status, auth := makeRequest()
	assert.Equal(t, http.StatusOK, status,
		"request through Pomerium should succeed when upstream token is injected")
	assert.Equal(t, "Bearer "+seededUpstreamToken, auth,
		"upstream should receive the seeded Authorization header injected by ext_proc")
}
