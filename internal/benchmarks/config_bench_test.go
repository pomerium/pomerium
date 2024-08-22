package benchmarks_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

func BenchmarkStartupLatency(b *testing.B) {
	for _, n := range []int{1, 10, 100, 1000, 10000} {
		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			for range b.N {
				env := testenv.New(b)
				up := upstreams.HTTP(nil)
				for i := range n {
					up.Route().
						From(env.SubdomainURL(fmt.Sprintf("from-%d", i))).
						PPL(`{"allow":{"and":[{"accept":"true"}]}}`)
				}
				env.AddUpstream(up)

				env.Start()
				snippets.WaitStartupComplete(b, env, 60*time.Minute)

				env.Stop()
			}
		})
	}
}

func BenchmarkAppendRoutes(b *testing.B) {
	for _, n := range []int{1, 10, 100, 1000, 10000} {
		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			for range b.N {
				env := testenv.New(b)
				up := upstreams.HTTP(nil)
				env.AddUpstream(up)

				env.Start()
				snippets.WaitStartupComplete(b, env)
				for i := range n {
					env.Add(up.Route().
						From(env.SubdomainURL(fmt.Sprintf("from-%d", i))).
						PPL(fmt.Sprintf(`{"allow":{"and":["email":{"is":"user-%d@example.com"}]}}`, i)))
				}
				env.Stop()
			}
		})
	}
}
