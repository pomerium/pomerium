package controlplane_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
)

// TestXDSRouteSurvivesRemoveAndRestore puts a databroker config record that
// carries some routes, replaces it with one that carries only some of them or
// deletes it, and immediately puts the full record back. Once the full record
// is back, all of its routes must work again.
//
// Whether a flip leaves a route unreachable depends on timing, so the test
// cycles through every route count and every kept subset several times.
func TestXDSRouteSurvivesRemoveAndRestore(t *testing.T) {
	const (
		maxRoutes    = 4
		flips        = 200
		recoveryWait = 30 * time.Second
	)

	e := newXDSEnv(t)
	routes := make([]*configpb.Route, maxRoutes)
	for i := range routes {
		routes[i] = e.route(fmt.Sprintf("flip-%d", i))
	}
	urls := func(indexes []int) []string {
		var urls []string
		for _, i := range indexes {
			urls = append(urls, routes[i].GetFrom())
		}
		return urls
	}

	// put stores the record with the given routes, or deletes it when there
	// are none
	put := func(indexes []int) {
		if len(indexes) == 0 {
			e.deleteConfig("flip")
			return
		}
		cfg := &configpb.Config{Name: "flip"}
		for _, i := range indexes {
			cfg.Routes = append(cfg.Routes, routes[i])
		}
		e.putConfig("flip", cfg)
	}

	// for every n up to maxRoutes, the first n routes form the full set and
	// every proper subset of them is kept, including none, which deletes the
	// record
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
			ok, last := e.reachable(recoveryWait, urls(s.full)...)
			require.Truef(t, ok, "flip %d: routes %v never became reachable, last statuses %v", flip, s.full, last)
			current = s.full
		}

		// the xDS exchange for this flip, shown if a route stays unreachable
		xdsLog := e.recordXDS()
		put(s.kept)
		put(s.full)
		ok, last := e.reachable(recoveryWait, urls(s.full)...)
		if !ok {
			t.Fatalf("flip %d: routes %v were restored after keeping only %v, but after %s the statuses are %v\nxDS log for this flip:%s",
				flip, s.full, s.kept, recoveryWait, last, formatXDSLog(xdsLog))
		}
		xdsLog.Close()
	}
}
