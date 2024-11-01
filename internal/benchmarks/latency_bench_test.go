package benchmarks_test

import (
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"testing"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/stretchr/testify/assert"
)

var numRoutes int

func init() {
	flag.IntVar(&numRoutes, "routes", 100, "number of routes")
}

func TestRequestLatency(t *testing.T) {
	env := testenv.New(t, testenv.Silent())
	users := []*scenarios.User{}
	for i := range numRoutes {
		users = append(users, &scenarios.User{
			Email:     fmt.Sprintf("user%d@example.com", i),
			FirstName: fmt.Sprintf("Firstname%d", i),
			LastName:  fmt.Sprintf("Lastname%d", i),
		})
	}
	env.Add(scenarios.NewIDP(users))

	up := upstreams.HTTP(nil)
	up.Handle("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("OK"))
	})
	routes := make([]testenv.Route, numRoutes)
	for i := range numRoutes {
		routes[i] = up.Route().
			From(env.SubdomainURL(fmt.Sprintf("from-%d", i))).
			PPL(fmt.Sprintf(`{"allow":{"and":["email":{"is":"user%d@example.com"}]}}`, i))
	}
	env.AddUpstream(up)

	env.Start()
	snippets.WaitStartupComplete(env)

	out := testing.Benchmark(func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			// rec := env.NewLogRecorder(testenv.WithSkipCloseDelay())
			for pb.Next() {
				idx := rand.IntN(numRoutes)
				resp, err := up.Get(routes[idx], upstreams.AuthenticateAs(fmt.Sprintf("user%d@example.com", idx)))
				if !assert.NoError(b, err) {
					// rec.DumpToFile(filepath.Join("testdata", strings.ReplaceAll(b.Name(), "/", "_")))
					return
				}

				assert.Equal(b, resp.StatusCode, 200)
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				assert.NoError(b, err)
				assert.Equal(b, "OK", string(body))
			}
		})
	})
	t.Log(out)
	t.Logf("req/s: %f", float64(out.N)/out.T.Seconds())

	env.Stop()
}
