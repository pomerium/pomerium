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

// xdsEnv is a running Pomerium with a bare upstream, for tests that change
// what envoy serves through databroker config records.
type xdsEnv struct {
	testenv.Environment
	t           *testing.T
	ctx         context.Context
	dbClient    databrokerpb.DataBrokerServiceClient
	httpClient  *http.Client
	upstreamURL string
}

func newXDSEnv(t *testing.T) *xdsEnv {
	env := testenv.New(t)
	// trace level names the resources in each xDS response, for the failure
	// messages
	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		cfg.Options.LogLevel = config.LogLevelTrace
	}))
	up := upstreams.HTTP(nil)
	up.Handle("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	env.AddUpstream(up)

	env.Start()
	snippets.WaitStartupComplete(env)

	return &xdsEnv{
		Environment: env,
		t:           t,
		ctx:         env.Context(),
		dbClient:    env.NewDataBrokerServiceClient(),
		httpClient:  upstreams.NewHTTPClient(env.ServerCAs(), &upstreams.RequestOptions{}),
		upstreamURL: "http://" + up.Addr().Value(),
	}
}

// route returns a public route from the subdomain name to the upstream.
func (e *xdsEnv) route(name string) *configpb.Route {
	return &configpb.Route{
		Id:                               &name,
		Name:                             &name,
		From:                             e.SubdomainURL(name).Value(),
		To:                               []string{e.upstreamURL},
		AllowPublicUnauthenticatedAccess: true,
	}
}

// putConfig stores a config record.
func (e *xdsEnv) putConfig(id string, cfg *configpb.Config) {
	e.t.Helper()
	e.putRecord(id, cfg, nil)
}

// deleteConfig deletes a config record.
func (e *xdsEnv) deleteConfig(id string) {
	e.t.Helper()
	e.putRecord(id, &configpb.Config{Name: id}, timestamppb.Now())
}

func (e *xdsEnv) putRecord(id string, cfg *configpb.Config, deletedAt *timestamppb.Timestamp) {
	e.t.Helper()
	data := protoutil.NewAny(cfg)
	_, err := e.dbClient.Put(e.ctx, &databrokerpb.PutRequest{Records: []*databrokerpb.Record{
		{Type: data.TypeUrl, Id: id, Data: data, DeletedAt: deletedAt},
	}})
	require.NoError(e.t, err)
}

// status returns the status of a GET of the URL, or the error.
func (e *xdsEnv) status(url string) string {
	e.t.Helper()
	reqCtx, cancel := context.WithTimeout(e.ctx, 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	require.NoError(e.t, err)
	res, err := e.httpClient.Do(req)
	if err != nil {
		return err.Error()
	}
	_ = res.Body.Close()
	return res.Status
}

// reachable reports whether every URL answers 200 on the same attempt within
// wait, and the status of each on the last attempt.
func (e *xdsEnv) reachable(wait time.Duration, urls ...string) (bool, map[string]string) {
	e.t.Helper()
	last := map[string]string{}
	all := assertEventually(func() bool {
		for _, url := range urls {
			last[url] = e.status(url)
		}
		return !slices.ContainsFunc(urls, func(url string) bool { return last[url] != "200 OK" })
	}, wait, 25*time.Millisecond)
	return all, last
}

// recordXDS records the xDS exchange from now on.
func (e *xdsEnv) recordXDS() *testenv.LogRecorder {
	return e.NewLogRecorder(testenv.WithSkipCloseDelay(), testenv.WithFilters(func(entry map[string]any) bool {
		message, _ := entry["message"].(string)
		return strings.HasPrefix(message, "xdsmgr: ") || message == "controlplane: built discovery resources"
	}))
}

// formatXDSLog formats a recorded xDS exchange for a failure message.
func formatXDSLog(rec *testenv.LogRecorder) string {
	var b strings.Builder
	for _, entry := range rec.Logs() {
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
