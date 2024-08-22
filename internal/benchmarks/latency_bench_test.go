package benchmarks_test

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/stretchr/testify/assert"
)

func BenchmarkRequestLatency(b *testing.B) {
	for _, n := range []int{1, 10, 100} {
		b.StopTimer()
		env := testenv.New(b)
		users := []*scenarios.User{}
		for i := range n {
			users = append(users, &scenarios.User{
				Email:     fmt.Sprintf("user%d@example.com", i),
				FirstName: fmt.Sprintf("Firstname%d", i),
				LastName:  fmt.Sprintf("Lastname%d", i),
			})
		}
		env.Add(scenarios.NewIDP(users))

		up := upstreams.HTTP(nil)
		up.Handle("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("OK"))
		})
		routes := make([]testenv.Route, n)
		for i := range n {
			routes[i] = up.Route().
				From(env.SubdomainURL(fmt.Sprintf("from-%d", i))).
				PPL(fmt.Sprintf(`{"allow":{"and":["email":{"is":"user%d@example.com"}]}}`, i))
		}
		env.AddUpstream(up)

		env.Start()
		snippets.WaitStartupComplete(b, env)

		b.StartTimer()

		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			indexes := rand.Perm(n)
			rec := env.NewLogRecorder(testenv.WithSkipCloseDelay())
			for i := range b.N {
				idx := indexes[i%n]
				resp, err := up.Get(routes[idx], upstreams.AuthenticateAs(fmt.Sprintf("user%d@example.com", idx)))
				if !assert.NoError(b, err) {
					rec.DumpToFile(filepath.Join("testdata", strings.ReplaceAll(b.Name(), "/", "_")))
					return
				}

				assert.Equal(b, resp.StatusCode, 200)
				body, err := io.ReadAll(resp.Body)
				assert.NoError(b, err)
				assert.Equal(b, "OK", string(body))
			}
		})

		env.Stop()
	}
}
