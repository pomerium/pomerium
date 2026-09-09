package e2e

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	databroker_service "github.com/pomerium/pomerium/databroker"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/pkg/cmd/pomerium"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity/manager"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// TestExtProcSurvivesOutboundReload reproduces
// https://github.com/pomerium/pomerium/issues/6730 end to end, in the order the
// deployment there goes through it:
//
//  1. Pomerium starts from the ingress controller's bootstrap config, which has
//     no installation_id. The controlplane builds the MCP ext_proc handler
//     right away, so the handler's databroker connection is dialed with the
//     bootstrap outbound options.
//  2. The console's "dashboard-settings" record arrives through the databroker
//     and the running config gains installation_id. Proxy and authorize rebuild
//     per config and re-dial; the controlplane keeps its startup connection.
//  3. The MCP route, with no upstream OAuth, serves requests: every request
//     looks up an upstream token in the databroker and gets "not found".
//  4. The upstream is redeployed. The ingress controller rewrites its record
//     with the new pod endpoints; that alone changes nothing about the outbound
//     connection, the route just follows the new upstream. MCP clients then
//     re-authenticate, the MCP token endpoint refreshes the IdP token into a
//     new session, and an earlier session is left holding a token the IdP now
//     rejects. The identity manager fails to refresh it, deletes it and records
//     a LastError event. The controlplane persists that event through its
//     cached connection, resolving it against the current config: the options
//     differ from startup, so the connection the ext_proc handler captured is
//     closed and re-dialed.
//  5. The MCP route must keep working. Before the fix every request failed
//     closed with a 502 because the token lookup hit the closed connection.
//
// The re-authentication is modeled by writing a session whose refresh token the
// IdP rejects.
func TestExtProcSurvivesOutboundReload(t *testing.T) {
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.RuntimeFlags == nil {
			cfg.Options.RuntimeFlags = make(config.RuntimeFlags)
		}
		cfg.Options.RuntimeFlags[config.RuntimeFlagMCP] = true
		cfg.Options.MCPAllowedClientIDDomains = []string{"*.localhost.pomerium.io"}
	}))
	const saUserID = "reload-user@example.com"
	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: saUserID}}))
	// refresh a session as soon as it is due rather than after the default cool-off
	env.AddOption(pomerium.WithDataBrokerServerOptions(databroker_service.WithManagerOptions(
		manager.WithSessionRefreshCoolOffDuration(100 * time.Millisecond),
	)))

	// two upstream "pods": the route points at A first, then is redeployed to B
	var hitsA, hitsB atomic.Int32
	upstreamA := "http://" + startPlainUpstream(t, env.Host(), &hitsA).Addr().String()
	upstreamB := "http://" + startPlainUpstream(t, env.Host(), &hitsB).Addr().String()

	env.Start()
	snippets.WaitStartupComplete(env)
	ctx := env.Context()
	dbClient := env.NewDataBrokerServiceClient()

	// 1+2: the ingress-controller route and the console settings arrive through the databroker.
	const routeID = "mcp-outbound-reload-route"
	fromURL := env.SubdomainURL("mcp-outbound-reload").Value()
	pushMCPRouteViaDatabroker(t, env, routeID, fromURL, upstreamA)
	settingsRec := env.NewLogRecorder(testenv.WithSkipCloseDelay())
	putConfigRecord(ctx, t, dbClient, "dashboard-settings", &configpb.Config{
		Name:     "dashboard-settings",
		Settings: &configpb.Settings{InstallationId: new("console-installation")},
	})
	// the per-config services re-dial for the new installation id
	settingsRec.WaitForMatch(map[string]any{"message": "outbound client connection has changed meaningfully, reloading"}, 20*time.Second)

	// 3: the MCP route works
	sa := &user.ServiceAccount{Id: "outbound-reload-sa", UserId: saUserID}
	_, err := user.PutServiceAccount(ctx, dbClient, sa)
	require.NoError(t, err)
	saJWT, err := cryptutil.SignServiceAccount(env.SharedSecret(), sa.Id, sa.UserId, time.Now(), null.Time{})
	require.NoError(t, err)
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
	var lastStatus int
	require.Eventuallyf(t, func() bool {
		lastStatus = makeRequest()
		return lastStatus == http.StatusOK && hitsA.Load() > 0
	}, 30*time.Second, 250*time.Millisecond, "precondition: MCP route never served (last status=%d)", lastStatus)

	// 4a: the upstream is redeployed; the ingress controller rewrites its record
	// with the new endpoint. The route follows, and nothing re-dials.
	const reloadMsg = "outbound client connection has changed meaningfully, reloading"
	redeployRec := env.NewLogRecorder(testenv.WithSkipCloseDelay(), testenv.WithFilters(func(m map[string]any) bool {
		return m["message"] == reloadMsg
	}))
	pushMCPRouteViaDatabroker(t, env, routeID, fromURL, upstreamB)
	require.Eventuallyf(t, func() bool {
		lastStatus = makeRequest()
		return hitsB.Load() > 0 || lastStatus == http.StatusBadGateway
	}, 30*time.Second, 250*time.Millisecond, "route change never propagated (last status=%d)", lastStatus)
	require.Equal(t, http.StatusOK, lastStatus, "MCP request after the upstream redeploy")
	require.Empty(t, redeployRec.Logs(), "an upstream redeploy must not reload the outbound connection")

	// 4b: a session left behind by an MCP re-authentication; its refresh fails at the IdP.
	deletionRec := env.NewLogRecorder(testenv.WithSkipCloseDelay())
	now := time.Now()
	_, err = session.Put(ctx, dbClient, &session.Session{
		Id:        "stale-mcp-session",
		UserId:    saUserID,
		ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		OauthToken: &session.OAuthToken{
			AccessToken:  "stale-access-token",
			RefreshToken: "revoked-refresh-token",
			TokenType:    "Bearer",
			ExpiresAt:    timestamppb.New(now),
		},
	})
	require.NoError(t, err)
	deletionRec.WaitForMatch(map[string]any{"message": "failed to refresh oauth2 token, deleting session"}, 30*time.Second)
	// ...and the controlplane persists the resulting LastError event through its
	// cached connection, resolving it against the current config.
	eventRec := env.NewLogRecorder(testenv.WithSkipCloseDelay())
	eventRec.WaitForMatch(map[string]any{
		"message":     "databroker/backend: put",
		"record-type": "type.googleapis.com/pomerium.events.LastError",
	}, 20*time.Second)

	// 5: the MCP route must still work
	for range 5 {
		require.Equal(t, http.StatusOK, makeRequest(), "MCP request after the outbound connection reload")
	}
}

func putConfigRecord(ctx context.Context, t *testing.T, client databrokerpb.DataBrokerServiceClient, id string, cfg *configpb.Config) {
	t.Helper()
	data := protoutil.NewAny(cfg)
	_, err := client.Put(ctx, &databrokerpb.PutRequest{Records: []*databrokerpb.Record{{Type: data.TypeUrl, Id: id, Data: data}}})
	require.NoError(t, err)
}

// startPlainUpstream starts a minimal HTTP server on host:0 that answers 200 to
// everything and counts requests. It stands in for an MCP upstream with no
// upstream OAuth.
func startPlainUpstream(t *testing.T, host string, hits *atomic.Int32) net.Listener {
	t.Helper()
	listener, err := testenv.Listen(t.Context(), host)
	require.NoError(t, err)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}),
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
