package controlplane_test

import (
	"context"
	"net/http"
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
		put(true)
		put(false)

		var last int
		ok := assertEventually(func() bool {
			last = status()
			return last == http.StatusOK
		}, 30*time.Second, 25*time.Millisecond)
		require.Truef(t, ok,
			"flip %d: the record carrying the route was restored, but the route still returns %d after 30s",
			i, last)
	}
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
