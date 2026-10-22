package databroker_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	databrokersvc "github.com/pomerium/pomerium/databroker"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	pomeriumgrpc "github.com/pomerium/pomerium/pkg/grpc"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// TestConfigSourceSurvivesLeaderChange runs Pomerium as one node of a two node
// databroker cluster and moves the leader between the nodes, as a raft
// election does. On each leader change the config syncer aborts with a server
// version mismatch and re-syncs its records. The config record carrying the
// route never changes, so the re-sync must not remove the route from envoy,
// not even briefly, and the route must keep working.
//
// Whether a leader change removes the route depends on timing, so the test
// moves the leader repeatedly.
func TestConfigSourceSurvivesLeaderChange(t *testing.T) {
	env := testenv.New(t)

	upstream, err := testenv.Listen(t.Context(), env.Host())
	require.NoError(t, err)
	upstreamSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = upstreamSrv.Serve(upstream) }()
	t.Cleanup(func() { _ = upstreamSrv.Close() })

	nodeBListener, err := testenv.Listen(t.Context(), env.Host())
	require.NoError(t, err)
	setCluster := func(o *config.Options, nodeID, leaderID string) {
		o.DataBroker.ClusterNodeID = null.StringFrom(nodeID)
		o.DataBroker.ClusterLeaderID = null.StringFrom(leaderID)
		o.DataBroker.ClusterNodes = config.DataBrokerClusterNodes{
			{ID: "node-a", GRPCAddress: fmt.Sprintf("http://%s:%d", env.Host(), env.Ports().Outbound.Value())},
			{ID: "node-b", GRPCAddress: "http://" + nodeBListener.Addr().String()},
		}
	}

	// node-a is the pomerium under test and starts as the leader
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		setCluster(cfg.Options, "node-a", "node-a")
	}))
	env.Start()
	snippets.WaitStartupComplete(env)
	ctx := env.Context()

	// node-b is a second databroker node, built the same way pomerium builds
	// its own. It starts as a follower replicating node-a.
	nodeBOptions := config.NewDefaultOptions()
	nodeBOptions.SharedKey = base64.StdEncoding.EncodeToString(env.SharedSecret())
	nodeBOptions.DataBroker.StorageType = "memory"
	setCluster(nodeBOptions, "node-b", "node-a")
	nodeB := databrokersvc.NewServer(noop.NewTracerProvider(), config.New(nodeBOptions))
	nodeB.OnConfigChange(ctx, config.New(nodeBOptions))
	t.Cleanup(nodeB.Stop)
	nodeBServer := grpc.NewServer()
	databrokerpb.RegisterDataBrokerServiceServer(nodeBServer, nodeB)
	go func() { _ = nodeBServer.Serve(nodeBListener) }()
	t.Cleanup(nodeBServer.Stop)

	nodeBConn, err := pomeriumgrpc.NewGRPCClientConn(ctx, &pomeriumgrpc.Options{
		Address:      nodeBListener.Addr().String(),
		SignedJWTKey: env.SharedSecret(),
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = nodeBConn.Close() })
	nodeBClient := databrokerpb.NewDataBrokerServiceClient(nodeBConn)

	// the route arrives the way the ingress controller delivers it
	routeID := "leader-change"
	fromURL := env.SubdomainURL("leader-change").Value()
	data := protoutil.NewAny(&configpb.Config{
		Name: "ingress-controller",
		Routes: []*configpb.Route{{
			Id:                               &routeID,
			Name:                             &routeID,
			From:                             fromURL,
			To:                               []string{"http://" + upstream.Addr().String()},
			AllowPublicUnauthenticatedAccess: true,
		}},
	})
	_, err = env.NewDataBrokerServiceClient().Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{Type: data.TypeUrl, Id: "ingress-controller", Data: data}},
	})
	require.NoError(t, err)

	httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
	status := func() int {
		reqCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, fromURL, nil)
		require.NoError(t, err)
		res, err := httpClient.Do(req)
		if err != nil {
			return 0
		}
		_ = res.Body.Close()
		return res.StatusCode
	}
	require.Eventually(t, func() bool { return status() == http.StatusOK },
		30*time.Second, 50*time.Millisecond, "route never became reachable")

	// node-b can only take over once it has replicated the record
	require.Eventually(t, func() bool {
		res, err := nodeBClient.Get(
			databrokerpb.WithOutgoingClusterRequestMode(ctx, databrokerpb.ClusterRequestModeLocal),
			&databrokerpb.GetRequest{Type: data.TypeUrl, Id: "ingress-controller"})
		return err == nil && res.GetRecord() != nil
	}, 30*time.Second, 50*time.Millisecond, "node-b never replicated the config record")

	const leaderChanges = 60
	for i := range leaderChanges {
		leaderID := []string{"node-b", "node-a"}[i%2]

		recorder := env.NewLogRecorder(testenv.WithSkipCloseDelay(), testenv.WithFilters(func(entry map[string]any) bool {
			switch entry["message"] {
			case "databroker/syncer: aborted sync due to mismatched versions":
				return entry["syncer-type"] == data.TypeUrl
			case "xdsmgr: sending resources":
				return entry["type-url"] == "type.googleapis.com/envoy.config.cluster.v3.Cluster" &&
					entry["removed-resource-count"] != float64(0)
			}
			return false
		}))

		setCluster(nodeBOptions, "node-b", leaderID)
		nodeB.OnConfigChange(ctx, config.New(nodeBOptions))
		env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
			setCluster(cfg.Options, "node-a", leaderID)
		}))

		var last int
		reachable := eventually(func() bool {
			last = status()
			return last == http.StatusOK
		}, 30*time.Second, 25*time.Millisecond)
		// let the resync finish before looking at what it did
		time.Sleep(500 * time.Millisecond)

		var resynced, removed bool
		for _, entry := range recorder.Logs() {
			switch entry["message"] {
			case "databroker/syncer: aborted sync due to mismatched versions":
				resynced = true
			case "xdsmgr: sending resources":
				removed = true
			}
		}
		require.Truef(t, resynced, "leader change %d (to %s) did not re-sync the config records", i, leaderID)
		require.Falsef(t, removed,
			"leader change %d (to %s) removed the route's cluster from envoy, although the config record carrying the route never changed",
			i, leaderID)
		require.Truef(t, reachable,
			"the route still returns %d 30s after leader change %d (to %s); envoy clusters: %v",
			last, i, leaderID, envoyClusters(env))
	}
}

func envoyClusters(env testenv.Environment) []string {
	res, err := http.Get(fmt.Sprintf("http://%s:%d/clusters", env.Host(), env.Ports().EnvoyAdmin.Value()))
	if err != nil {
		return []string{"error: " + err.Error()}
	}
	defer res.Body.Close()
	var names []string
	scanner := bufio.NewScanner(res.Body)
	for scanner.Scan() {
		name, _, ok := strings.Cut(scanner.Text(), "::")
		if ok && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	return names
}

func eventually(condition func() bool, waitFor, tick time.Duration) bool {
	deadline := time.Now().Add(waitFor)
	for {
		if condition() {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(tick)
	}
}
