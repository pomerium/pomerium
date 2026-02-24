package selftests_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
)

func TestParallelEnvironments(t *testing.T) {
	for _, name := range []string{"env1", "env2"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			env := testenv.New(t)
			up := upstreams.HTTP(nil)
			up.Handle("/", func(w http.ResponseWriter, _ *http.Request) {
				w.Write([]byte("OK"))
			})
			route := up.Route().
				From(env.SubdomainURL("test-" + name)).
				Policy(func(p *config.Policy) {
					p.AllowPublicUnauthenticatedAccess = true
				})
			env.AddUpstream(up)

			env.Start()
			snippets.WaitStartupComplete(env)

			resp, err := up.Get(route)
			require.NoError(t, err)
			require.Equal(t, http.StatusOK, resp.StatusCode)
		})
	}
}
