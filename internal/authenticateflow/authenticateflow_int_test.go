package authenticateflow_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
)

func newHTTPUpstream(
	env testenv.Environment, subdomain string,
) (upstreams.HTTPUpstream, testenv.Route) {
	up := upstreams.HTTP(nil)
	up.Handle("/", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "hello world") })
	route := up.Route().
		From(env.SubdomainURL(subdomain)).
		To(values.Bind(up.Addr(), func(addr string) string {
			// override the target protocol to use http://
			return fmt.Sprintf("http://%s", addr)
		})).
		Policy(func(p *config.Policy) { p.AllowAnyAuthenticatedUser = true })
	env.AddUpstream(up)
	return up, route
}

func TestMultiDomainLogin(t *testing.T) {
	t.Parallel()
	env := testenv.New(t)

	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "test@example.com"}}))

	// Create three routes to be linked via multi-domain login...
	upstreamA, routeA := newHTTPUpstream(env, "a")
	upstreamB, routeB := newHTTPUpstream(env, "b")
	upstreamC, routeC := newHTTPUpstream(env, "c")
	// ...and one route that will not be involved.
	upstreamD, routeD := newHTTPUpstream(env, "d")

	// Configure route A to redirect through routes B and C on login.
	routeA.Policy(func(p *config.Policy) {
		p.DependsOn = []string{
			strings.TrimPrefix(routeB.URL().Value(), "https://"),
			strings.TrimPrefix(routeC.URL().Value(), "https://"),
		}
	})

	env.Start()
	snippets.WaitStartupComplete(env)

	// By default the testenv code will use a separate http.Client for each
	// separate route. Instead we specifically want to test the cross-route
	// behavior for a single client.
	cj, err := cookiejar.New(nil)
	require.NoError(t, err)
	sharedClient := http.Client{Jar: cj}
	withSharedClient := upstreams.ClientHook(
		func(_ *http.Client) *http.Client { return &sharedClient })

	assertResponseOK := func(resp *http.Response, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	assertRedirect := func(resp *http.Response, err error) {
		t.Helper()
		require.NoError(t, err)
		assert.Equal(t, http.StatusFound, resp.StatusCode)
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	// Log in to the first route.
	assertResponseOK(upstreamA.Get(routeA, withSharedClient, upstreams.AuthenticateAs("test@example.com")))

	// The client should also be authenticated for routes B and C without any
	// additional login redirects.
	sharedClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	assertResponseOK(upstreamB.Get(routeB, withSharedClient))
	assertResponseOK(upstreamC.Get(routeC, withSharedClient))

	// The client should not be authenticated for route D.
	assertRedirect(upstreamD.Get(routeD, withSharedClient))
}
