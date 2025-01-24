package benchmarks_test

import (
	"flag"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"testing"
	"time"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/envutil"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/stretchr/testify/assert"
)

var (
	numRoutes     int
	dumpErrLogs   bool
	enableTracing bool
	publicRoutes  bool
)

func init() {
	flag.IntVar(&numRoutes, "routes", 100, "number of routes")
	flag.BoolVar(&dumpErrLogs, "dump-err-logs", false, "if the test fails, write all captured logs to a file (testdata/<test-name>)")
	flag.BoolVar(&enableTracing, "enable-tracing", false, "enable tracing")
	flag.BoolVar(&publicRoutes, "public-routes", false, "use public unauthenticated routes")
}

func TestRequestLatency(t *testing.T) {
	resume := envutil.PauseProfiling(t)
	var env testenv.Environment
	if enableTracing {
		receiver := scenarios.NewOTLPTraceReceiver()
		env = testenv.New(t, testenv.Silent(), testenv.WithTraceClient(receiver.NewGRPCClient()))
		env.Add(receiver)
	} else {
		env = testenv.New(t, testenv.Silent())
	}

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
			From(env.SubdomainURL(fmt.Sprintf("from-%d", i)))
		if publicRoutes {
			routes[i] = routes[i].Policy(func(p *config.Policy) { p.AllowPublicUnauthenticatedAccess = true })
		} else {
			routes[i] = routes[i].PPL(fmt.Sprintf(`{"allow":{"and":["email":{"is":"user%d@example.com"}]}}`, i))
		}
	}
	env.AddUpstream(up)

	env.Start()
	snippets.WaitStartupComplete(env, 1*time.Hour)
	resume()

	out := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			var rec *testenv.LogRecorder
			if dumpErrLogs {
				rec = env.NewLogRecorder(testenv.WithSkipCloseDelay())
			}
			for pb.Next() {
				idx := rand.IntN(numRoutes)
				resp, err := up.Get(routes[idx], upstreams.AuthenticateAs(fmt.Sprintf("user%d@example.com", idx)))
				if !assert.NoError(b, err) {
					filename := "TestRequestLatency_err.log"
					if dumpErrLogs {
						rec.DumpToFile(filename)
						b.Logf("test logs written to %s", filename)
					}
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
