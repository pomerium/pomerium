package controlplane_test

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// TestXDSRouteSurvivesRemoveAndRestore puts a databroker config record that
// carries some routes, replaces it with one that carries only some of them or
// deletes it, and immediately puts the full record back. Once the full record
// is back, all of its routes must work again.
//
// Whether a flip leaves a route unreachable depends on timing, so the test
// cycles through every combination of routes several times.
func TestXDSRouteSurvivesRemoveAndRestore(t *testing.T) {
	const (
		maxRoutes    = 4
		flips        = 200
		recoveryWait = 30 * time.Second
	)

	env := testenv.New(t)
	// trace level names the resources in each xDS response, for the failure
	// message
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		cfg.Options.LogLevel = config.LogLevelTrace
	}))

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
	names := make([]string, maxRoutes)
	fromURLs := make([]string, maxRoutes)
	for i := range names {
		names[i] = fmt.Sprintf("flip-%d", i)
		fromURLs[i] = env.SubdomainURL(names[i]).Value()
	}

	// put stores the record with the given routes, or deletes it when there
	// are none
	put := func(routes []int) {
		cfg := &configpb.Config{Name: "flip"}
		for _, i := range routes {
			cfg.Routes = append(cfg.Routes, &configpb.Route{
				Id:                               &names[i],
				Name:                             &names[i],
				From:                             fromURLs[i],
				To:                               []string{"http://" + listener.Addr().String()},
				AllowPublicUnauthenticatedAccess: true,
			})
		}
		data := protoutil.NewAny(cfg)
		record := &databrokerpb.Record{Type: data.TypeUrl, Id: "flip", Data: data}
		if len(routes) == 0 {
			record.DeletedAt = timestamppb.Now()
		}
		_, err := dbClient.Put(ctx, &databrokerpb.PutRequest{Records: []*databrokerpb.Record{record}})
		require.NoError(t, err)
	}

	httpClient := upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{})
	status := func(fromURL string) int {
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
	// reachable reports whether every route works within recoveryWait, and
	// the last status of each
	reachable := func(routes []int) (bool, map[string]int) {
		last := map[string]int{}
		ok := assertEventually(func() bool {
			all := true
			for _, i := range routes {
				if last[names[i]] != http.StatusOK {
					last[names[i]] = status(fromURLs[i])
				}
				all = all && last[names[i]] == http.StatusOK
			}
			return all
		}, recoveryWait, 25*time.Millisecond)
		return ok, last
	}

	// every non-empty set of routes, with every proper subset of it kept,
	// including none, which deletes the record
	type scenario struct{ full, kept []int }
	var scenarios []scenario
	for n := 1; n <= maxRoutes; n++ {
		full := make([]int, n)
		for i := range full {
			full[i] = i
		}
		for mask := range 1<<n - 1 {
			var kept []int
			for _, i := range full {
				if mask&(1<<i) != 0 {
					kept = append(kept, i)
				}
			}
			scenarios = append(scenarios, scenario{full, kept})
		}
	}

	var current []int
	for flip := range flips {
		s := scenarios[flip%len(scenarios)]

		// the previous flip may already have left exactly these routes working
		if !slices.Equal(current, s.full) {
			put(s.full)
			ok, last := reachable(s.full)
			require.Truef(t, ok, "flip %d: routes %v never became reachable, last statuses %v", flip, s.full, last)
			current = s.full
		}

		// the xDS exchange for this flip, shown if a route stays unreachable
		xdsLog := env.NewLogRecorder(testenv.WithSkipCloseDelay(), testenv.WithFilters(func(entry map[string]any) bool {
			message, _ := entry["message"].(string)
			return strings.HasPrefix(message, "xdsmgr: ") || message == "controlplane: built discovery resources"
		}))
		put(s.kept)
		put(s.full)
		ok, last := reachable(s.full)
		entries := xdsLog.Logs()
		require.Truef(t, ok,
			"flip %d: routes %v were restored after keeping only %v, but after %s the statuses are %v\nxDS log for this flip:%s",
			flip, s.full, s.kept, recoveryWait, last, formatXDSLog(entries))
	}
}

func formatXDSLog(entries []map[string]any) string {
	var b strings.Builder
	for _, entry := range entries {
		fmt.Fprintf(&b, "\n  %v", entry["message"])
		if typeURL, ok := entry["type-url"].(string); ok {
			fmt.Fprintf(&b, " %s", typeURL[strings.LastIndex(typeURL, ".")+1:])
		}
		for _, key := range slices.Sorted(maps.Keys(entry)) {
			switch key {
			case "message", "type-url", "time", "level", "server-name", "service":
			default:
				fmt.Fprintf(&b, " %s=%v", key, entry[key])
			}
		}
	}
	return b.String()
}

// assertEventually is like assert.Eventually, but runs the condition on the
// calling goroutine, so the condition can record what it saw.
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
