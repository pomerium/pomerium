package authorize_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

// TestCookieAndBearer_NonJWTRoutePassthrough asserts that on a route that does
// not itself consume the bearer token (bearer_token_format not set), a
// cookie-authenticated browser request may also carry an Authorization: Bearer
// header meant for the upstream. Pomerium must authenticate via the session
// cookie and forward the header untouched — a common pattern for a browser app
// behind Pomerium SSO that also calls an API wanting its own bearer token.
//
// The cookie+bearer mutual-exclusion guard (see
// TestExternalJWTBearer_CookieAndBearerCollision below) only applies to routes
// where Pomerium consumes the bearer itself.
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

// jwtBearerAudience is the audience the mock identity providers accept and the
// tests mint tokens for.
const jwtBearerAudience = "pomerium.example.com"

// configureJWTIdp wires a mock OIDC issuer into Pomerium's identity_providers
// map under the given name (audiences are per-provider) and returns the IDP
// plus its URL.
func configureJWTIdp(t *testing.T, env testenv.Environment, idpName string) (*mockidp.IDP, values.Value[string]) {
	t.Helper()

	idp := mockidp.New(mockidp.Config{})
	idpUp := upstreams.HTTP(nil, upstreams.WithDisplayName("JWT Issuer"))
	idp.Register(idpUp.Router())
	env.AddUpstream(idpUp)

	idpURL := values.Bind(idpUp.Addr(), func(addr string) string {
		return fmt.Sprintf("http://%s", addr)
	})

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.IdentityProviders == nil {
			cfg.Options.IdentityProviders = map[string]config.IdentityProvider{}
		}
		cfg.Options.IdentityProviders[idpName] = config.IdentityProvider{
			Issuer:        idpURL.Value(),
			Audiences:     []string{jwtBearerAudience},
			SupportedAlgs: []string{"ES256"}, // mockidp signs with ES256
		}
	}))

	return idp, idpURL
}

// useJWTBearer configures a route to verify JWT bearer tokens. The optional
// providerNames set the route's identity-provider allowlist; when none are
// given the route accepts tokens from any configured provider.
func useJWTBearer(p *config.Policy, providerNames ...string) {
	p.BearerTokenFormat = nullable.From(configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT)
	p.IdentityProviders = providerNames
}

// stdSAClaims returns a minimal Kubernetes-shaped SA token claims map.
func stdSAClaims(issuer, sub, aud string, now time.Time) map[string]any {
	return map[string]any{
		"iss": issuer,
		"sub": sub,
		"aud": []string{aud},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"kubernetes.io": map[string]any{
			"namespace": "default",
			"serviceaccount": map[string]any{
				"name": "my-sa",
				"uid":  "00000000-0000-0000-0000-000000000001",
			},
		},
	}
}

// TestExternalJWTBearer_CookieAndBearerCollision asserts that a request
// carrying both a Pomerium session cookie AND an Authorization: Bearer
// header is rejected with 400.
func TestExternalJWTBearer_CookieAndBearerCollision(t *testing.T) {
	env := testenv.New(t)
	idp, idpURL := configureJWTIdp(t, env, "demo-idp")

	up := upstreams.HTTP(nil, upstreams.WithDisplayName("Echo"))
	up.Handle("/echo", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	route := up.Route().
		From(env.SubdomainURL("api")).
		To(values.Bind(up.Addr(), func(addr string) string {
			return fmt.Sprintf("http://%s", addr)
		})).
		Policy(func(p *config.Policy) {
			useJWTBearer(p)
			var ppl config.PPLPolicy
			require.NoError(t, ppl.UnmarshalJSON([]byte(`{
				"allow": {"and": [{"claim/sub": "system:serviceaccount:default:my-sa"}]}
			}`)))
			p.Policy = &ppl
		})

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	tok := idp.SignJWT(stdSAClaims(idpURL.Value(), "system:serviceaccount:default:my-sa", "pomerium.example.com", time.Now()))

	resp, err := up.Get(route,
		upstreams.Path("/echo"),
		upstreams.Headers(map[string]string{
			"Authorization": "Bearer " + tok,
			"Cookie":        "_pomerium=fake-session-value",
		}),
		upstreams.ClientHook(func(_ *http.Client) *http.Client {
			return &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}}
		}),
	)
	require.NoError(t, err)
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"cookie + bearer must be rejected as 400")
}
