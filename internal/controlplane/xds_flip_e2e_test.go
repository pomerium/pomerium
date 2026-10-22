package controlplane_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// TestXDSRouteSurvivesRemoveAndRestore removes the databroker config record
// that carries a route and immediately puts it back. Once the record is back,
// the route must work again.
//
// Whether a flip leaves the route unreachable depends on timing, so the test
// flips the record repeatedly within a time budget.
func TestXDSRouteSurvivesRemoveAndRestore(t *testing.T) {
	env := testenv.New(t)

	listener, err := testenv.Listen(t.Context(), env.Host())
	require.NoError(t, err)
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(func() { _ = srv.Close() })

	env.Start()
	snippets.WaitStartupComplete(env)

	ctx := env.Context()
	dbClient := env.NewDataBrokerServiceClient()
	fromURL := env.SubdomainURL("flip").Value()

	routeID := "flip"
	data := protoutil.NewAny(&configpb.Config{
		Name: "ingress-controller",
		Routes: []*configpb.Route{{
			Id:                               &routeID,
			Name:                             &routeID,
			From:                             fromURL,
			To:                               []string{"http://" + listener.Addr().String()},
			AllowPublicUnauthenticatedAccess: true,
		}},
	})
	put := func(deleted bool) {
		record := &databrokerpb.Record{Type: data.TypeUrl, Id: "ingress-controller", Data: data}
		if deleted {
			record.DeletedAt = timestamppb.Now()
		}
		_, err := dbClient.Put(ctx, &databrokerpb.PutRequest{Records: []*databrokerpb.Record{record}})
		require.NoError(t, err)
	}

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

	put(false)
	require.Eventually(t, func() bool { return status() == http.StatusOK },
		30*time.Second, 50*time.Millisecond, "route never became reachable")

	deadline := time.Now().Add(60 * time.Second)
	for i := 0; time.Now().Before(deadline); i++ {
		// the xDS exchange for this flip, shown if the route stays unreachable
		xdsLog := env.NewLogRecorder(testenv.WithSkipCloseDelay(), testenv.WithFilters(func(entry map[string]any) bool {
			message, _ := entry["message"].(string)
			return strings.HasPrefix(message, "xdsmgr: ") || message == "controlplane: built discovery resources"
		}))
		put(true)
		put(false)

		var last int
		ok := assertEventually(func() bool {
			last = status()
			return last == http.StatusOK
		}, 30*time.Second, 25*time.Millisecond)
		entries := xdsLog.Logs()
		require.Truef(t, ok,
			"flip %d: the record carrying the route was restored, but the route still returns %d after 30s\nxDS log for this flip:%s",
			i, last, formatXDSLog(entries))
	}
}

func formatXDSLog(entries []map[string]any) string {
	var b strings.Builder
	for _, entry := range entries {
		fmt.Fprintf(&b, "\n  %v", entry["message"])
		if typeURL, ok := entry["type-url"].(string); ok {
			fmt.Fprintf(&b, " %s", typeURL[strings.LastIndex(typeURL, ".")+1:])
		}
		for _, key := range []string{"nonce", "latest-nonce", "resources", "removed-resources", "cluster-count", "route-configuration-count"} {
			if value, ok := entry[key]; ok {
				fmt.Fprintf(&b, " %s=%v", key, value)
			}
		}
	}
	return b.String()
}

func assertEventually(condition func() bool, waitFor, tick time.Duration) bool {
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
