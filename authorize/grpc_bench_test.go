package authorize

import (
	"fmt"
	"testing"

	"github.com/pomerium/pomerium/config"
)

// BenchmarkGetMatchingPolicy measures a.getMatchingPolicy, which linearly
// scans every configured policy computing its RouteID until it finds the one
// matching the request's route ID.
func BenchmarkGetMatchingPolicy(b *testing.B) {
	for _, idType := range []struct {
		name     string
		explicit bool
	}{
		{name: "generated"},
		{name: "explicit", explicit: true},
	} {
		b.Run("id="+idType.name, func(b *testing.B) {
			for _, n := range []int{100, 1000, 10000} {
				b.Run(fmt.Sprintf("policies=%d", n), func(b *testing.B) {
					policies := make([]config.Policy, n)
					for i := range policies {
						to, err := config.ParseWeightedUrls(fmt.Sprintf("https://to-%d.example.com", i))
						if err != nil {
							b.Fatal(err)
						}
						policies[i] = config.Policy{
							From: fmt.Sprintf("https://from-%d.example.com", i),
							To:   to,
						}
						if idType.explicit {
							policies[i].ID = fmt.Sprintf("route-%d", i)
						}
					}

					a := &Authorize{}
					a.currentConfig.Store(config.New(&config.Options{Policies: policies}))

					// Look up a route in the middle of the set so every benchmark
					// pays for roughly half of a full scan.
					mid := n / 2
					routeID, err := policies[mid].RouteID()
					if err != nil {
						b.Fatal(err)
					}

					b.ReportAllocs()
					b.ResetTimer()
					for b.Loop() {
						if p := a.getMatchingPolicy(routeID); p != &policies[mid] {
							b.Fatal("matched the wrong policy")
						}
					}
				})
			}
		})
	}
}

// BenchmarkWithQuerierForCheckRequest measures a.withQuerierForCheckRequest,
// which builds the NewQuerier/NewCachingQuerier (and, when sync queriers are
// enabled, NewTypedQuerier/NewFallbackQuerier) chain used for every Check
// call. syncQueriers is left empty here, so this measures the
// NewQuerier+NewCachingQuerier path only, not the synced-data fallback path.
func BenchmarkWithQuerierForCheckRequest(b *testing.B) {
	a := &Authorize{}
	a.state.Store(&authorizeState{})

	ctx := b.Context()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = a.withQuerierForCheckRequest(ctx)
	}
}
