package metrics_test

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

func TestScrapeMetricsEndpoint(t *testing.T) {
	t.Skip("this test is for profiling purposes only")

	env := testenv.New(t, testenv.WithTraceDebugFlags(testenv.StandardTraceDebugFlags))
	upstream := upstreams.HTTP(nil)
	upstream.Handle("/test", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("OK"))
	})

	routes := []testenv.Route{}
	for i := range 10 {
		routes = append(routes, upstream.Route().
			From(env.SubdomainURL(fmt.Sprintf("test-%d", i))).
			Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true }))
	}
	env.AddUpstream(upstream)
	env.Start()
	snippets.WaitStartupComplete(env)

	for _, r := range routes {
		resp, err := upstream.Get(r, upstreams.Path("/test"))
		assert.NoError(t, err)
		data, err := io.ReadAll(resp.Body)
		assert.NoError(t, err)
		resp.Body.Close()
		assert.Equal(t, "OK", string(data))
	}

	metricsURL := fmt.Sprintf("http://%s/metrics", env.Ports().Metrics.Value())

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	var durations []time.Duration
	var totalBytes int64
	var errors int

	pct := 0
	niter := 200
	for i := 0; i < niter; i++ {
		pct = i * 100 / niter
		if pct%10 == 0 {
			t.Log(pct, "%")
		}

		start := time.Now()
		resp, err := client.Get(metricsURL)
		elapsed := time.Since(start)

		if err != nil {
			t.Logf("Request %d failed: %v", i, err)
			errors++
			continue
		}

		nb, err := io.Copy(io.Discard, resp.Body)
		if err != nil {
			resp.Body.Close()
			errors++
			continue
		}
		resp.Body.Close()

		durations = append(durations, elapsed)
		totalBytes += nb
	}

	if len(durations) > 0 {
		sort.Slice(durations, func(i, j int) bool {
			return durations[i] < durations[j]
		})

		var total time.Duration
		for _, d := range durations {
			total += d
		}

		t.Logf("Metrics scraping statistics:")
		t.Logf("  Successful requests: %d", len(durations))
		t.Logf("  Failed requests: %d", errors)
		t.Logf("  Total bytes: %d", totalBytes)
		t.Logf("  Avg bytes per request: %.2f", float64(totalBytes)/float64(len(durations)))
		t.Logf("  Min: %v", durations[0])
		t.Logf("  Max: %v", durations[len(durations)-1])
		t.Logf("  Avg: %v", total/time.Duration(len(durations)))
		t.Logf("  p50: %v", durations[len(durations)*50/100])
		t.Logf("  p90: %v", durations[len(durations)*90/100])
		t.Logf("  p95: %v", durations[len(durations)*95/100])
		t.Logf("  p99: %v", durations[len(durations)*99/100])
	} else {
		t.Logf("No successful requests made")
	}

	t.Logf("metrics endpoint: %s", metricsURL)

	env.Stop()
}
