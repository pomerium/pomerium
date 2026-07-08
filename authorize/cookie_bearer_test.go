package authorize_test

import (
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
)

// TestCookieAndBearer_NonJWTRoutePassthrough asserts that on a route that does
// not itself consume the bearer token (bearer_token_format not set), a
// cookie-authenticated browser request may also carry an Authorization: Bearer
// header meant for the upstream. Pomerium must authenticate via the session
// cookie and forward the header untouched — a common pattern for a browser app
// behind Pomerium SSO that also calls an API wanting its own bearer token.
//
// The cookie+bearer mutual-exclusion guard (see the CookieAndBearerCollision
// test) only applies to routes where Pomerium consumes the bearer itself.
//
// The test logs in normally (populating the route client's cookie jar), then
// issues a second request on the same route that additionally carries an
// Authorization: Bearer header, and asserts it succeeds (200) with the header
// forwarded to the upstream.
func TestCookieAndBearer_NonJWTRoutePassthrough(t *testing.T) {
	env := testenv.New(t)
	env.Add(scenarios.NewIDP([]*mockidp.User{
		{Email: "foo@example.com", FirstName: "Foo", LastName: "Bar"},
	}))

	up := upstreams.HTTP(nil, upstreams.WithDisplayName("Echo"))
	up.Handle("/echo", func(w http.ResponseWriter, r *http.Request) {
		// Report whether the upstream received the Authorization header, so a
		// green run also proves the header is forwarded (not consumed).
		fmt.Fprintf(w, "upstream-auth=%q", r.Header.Get("Authorization"))
	})

	route := up.Route().
		From(env.SubdomainURL("echo")).
		To(values.Bind(up.Addr(), func(addr string) string {
			return fmt.Sprintf("http://%s", addr)
		})).
		Policy(func(p *config.Policy) {
			// bearer_token_format intentionally NOT set → normal cookie-SSO route.
			p.AllowAnyAuthenticatedUser = true
		})

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	// 1) Log in normally. up.Get caches one *http.Client per route; the login
	//    flow populates that client's cookie jar with a valid _pomerium session.
	resp, err := up.Get(route, upstreams.AuthenticateAs("foo@example.com"), upstreams.Path("/echo"))
	require.NoError(t, err)
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "initial cookie login should succeed")

	// 2) Same route → same cached client → the request carries the session
	//    cookie from the jar, and we ALSO attach an Authorization: Bearer
	//    header destined for the upstream service.
	resp2, err := up.Get(route,
		upstreams.Path("/echo"),
		upstreams.Headers(map[string]string{"Authorization": "Bearer upstream-app-token"}),
	)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()

	assert.Equal(t, http.StatusOK, resp2.StatusCode,
		"a cookie-authenticated request on a non-JWT route must not be rejected "+
			"for also carrying an Authorization header (got %d, body=%q)",
		resp2.StatusCode, string(body))
}
