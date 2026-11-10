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
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	"github.com/pomerium/pomerium/pkg/endpoints"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

// TestExternalJWTBearer_HappyPath asserts a JWT-bearer authenticated request
// reaches the upstream when the route's bearer_token_format is jwt and the
// token's issuer/audience are trusted.
func TestExternalJWTBearer_HappyPath(t *testing.T) {
	env := testenv.New(t)
	idp, idpURL := configureJWTIdp(t, env, "demo-idp")

	const audience = "pomerium.example.com"

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
				"allow": {
					"and": [{
						"claim/sub": "system:serviceaccount:default:my-sa"
					}]
				}
			}`)))
			p.Policy = &ppl
		})

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	tok := idp.SignJWT(stdSAClaims(idpURL.Value(), "system:serviceaccount:default:my-sa", audience, time.Now()))

	resp, err := up.Get(route,
		upstreams.Path("/echo"),
		upstreams.Headers(map[string]string{"Authorization": "Bearer " + tok}),
	)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "expected 200; got %d body=%q", resp.StatusCode, string(body))
	assert.Contains(t, string(body), "ok")
}

// TestExternalJWTBearer_KubernetesNamespacePolicy asserts that a policy
// referencing `claim/kubernetes.io.namespace` (NO enrichment, no synthesized
// groups) matches correctly against the structured claim path.
func TestExternalJWTBearer_KubernetesNamespacePolicy(t *testing.T) {
	env := testenv.New(t)
	idp, idpURL := configureJWTIdp(t, env, "demo-idp")

	const audience = "pomerium.example.com"

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
				"allow": {
					"and": [{
						"claim/kubernetes.io.namespace": "platform"
					}]
				}
			}`)))
			p.Policy = &ppl
		})

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	now := time.Now()

	// Allowed: namespace=platform.
	allowed := idp.SignJWT(map[string]any{
		"iss": idpURL.Value(),
		"sub": "system:serviceaccount:platform:any-sa",
		"aud": []string{audience},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      "platform",
			"serviceaccount": map[string]any{"name": "any-sa"},
		},
	})

	resp, err := up.Get(route,
		upstreams.Path("/echo"),
		upstreams.Headers(map[string]string{"Authorization": "Bearer " + allowed}),
	)
	require.NoError(t, err)
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"namespace=platform token should be allowed by claim/kubernetes.io.namespace")

	// Denied: namespace=other.
	denied := idp.SignJWT(map[string]any{
		"iss": idpURL.Value(),
		"sub": "system:serviceaccount:other:any-sa",
		"aud": []string{audience},
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"kubernetes.io": map[string]any{
			"namespace":      "other",
			"serviceaccount": map[string]any{"name": "any-sa"},
		},
	})

	resp2, err := up.Get(route,
		upstreams.Path("/echo"),
		upstreams.Headers(map[string]string{"Authorization": "Bearer " + denied}),
	)
	require.NoError(t, err)
	defer resp2.Body.Close()
	io.ReadAll(resp2.Body)
	assert.NotEqual(t, http.StatusOK, resp2.StatusCode, "namespace=other should be denied")
}

// TestExternalJWTBearer_WrongAudience asserts a token minted for a different
// audience is rejected.
func TestExternalJWTBearer_WrongAudience(t *testing.T) {
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

	tok := idp.SignJWT(stdSAClaims(idpURL.Value(), "system:serviceaccount:default:my-sa", "someone-else", time.Now()))

	resp, err := up.Get(route,
		upstreams.Path("/echo"),
		upstreams.Headers(map[string]string{"Authorization": "Bearer " + tok}),
	)
	require.NoError(t, err)
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	assert.NotEqual(t, http.StatusOK, resp.StatusCode)
}

// TestExternalJWTBearer_NoBearerNoFallthrough asserts a JWT-only route with
// no Authorization header returns 401 (or non-200) — does NOT redirect to
// browser SSO.
func TestExternalJWTBearer_NoBearerNoFallthrough(t *testing.T) {
	env := testenv.New(t)
	configureJWTIdp(t, env, "demo-idp")

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

	// No Authorization header — request should be denied, NOT redirected
	// into an interactive sign-in.
	resp, err := up.Get(route,
		upstreams.Path("/echo"),
		upstreams.ClientHook(func(_ *http.Client) *http.Client {
			return &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			}}
		}),
	)
	require.NoError(t, err)
	defer resp.Body.Close()
	io.ReadAll(resp.Body)
	assert.NotEqual(t, http.StatusOK, resp.StatusCode,
		"a JWT-only route should not allow access without a bearer token")
}

// TestExternalJWTBearer_RouteProviderScoping asserts a route's
// identity_providers allowlist scopes which providers it accepts: a route
// allowing only idp-a rejects an idp-b token, while a route with no allowlist
// accepts tokens from either configured provider. (The session's IdpId ==
// provider name is asserted at the unit level in config's
// TestVerifyJWTAndCreateSession / TestCreateSessionForJWT_RouteProviderScoping.)
func TestExternalJWTBearer_RouteProviderScoping(t *testing.T) {
	env := testenv.New(t)
	idpA, idpAURL := configureJWTIdp(t, env, "idp-a")
	idpB, idpBURL := configureJWTIdp(t, env, "idp-b")

	up := upstreams.HTTP(nil, upstreams.WithDisplayName("Echo"))
	up.Handle("/echo", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	newPPL := func() *config.PPLPolicy {
		var ppl config.PPLPolicy
		require.NoError(t, ppl.UnmarshalJSON([]byte(`{"allow":{"and":[{"claim/sub":"svc"}]}}`)))
		return &ppl
	}
	toAddr := values.Bind(up.Addr(), func(addr string) string {
		return fmt.Sprintf("http://%s", addr)
	})

	// Route A: only idp-a is allowed.
	routeA := up.Route().
		From(env.SubdomainURL("api-a")).
		To(toAddr).
		Policy(func(p *config.Policy) {
			useJWTBearer(p, "idp-a")
			p.Policy = newPPL()
		})
	// Route B: no allowlist -> any configured provider is accepted.
	routeB := up.Route().
		From(env.SubdomainURL("api-b")).
		To(toAddr).
		Policy(func(p *config.Policy) {
			useJWTBearer(p)
			p.Policy = newPPL()
		})

	env.AddUpstream(up)
	env.Start()
	snippets.WaitStartupComplete(env)

	now := time.Now()
	mkTok := func(idp *mockidp.IDP, iss string) string {
		return idp.SignJWT(map[string]any{
			"iss": iss,
			"sub": "svc",
			"aud": []string{jwtBearerAudience},
			"exp": now.Add(time.Hour).Unix(),
			"iat": now.Unix(),
			"nbf": now.Unix(),
		})
	}
	tokA := mkTok(idpA, idpAURL.Value())
	tokB := mkTok(idpB, idpBURL.Value())

	status := func(route testenv.Route, tok string) int {
		resp, err := up.Get(route,
			upstreams.Path("/echo"),
			upstreams.Headers(map[string]string{"Authorization": "Bearer " + tok}),
		)
		require.NoError(t, err)
		defer resp.Body.Close()
		io.ReadAll(resp.Body)
		return resp.StatusCode
	}

	assert.Equal(t, http.StatusOK, status(routeA, tokA), "route allowing idp-a must accept idp-a token")
	assert.NotEqual(t, http.StatusOK, status(routeA, tokB), "route allowing only idp-a must reject idp-b token")
	assert.Equal(t, http.StatusOK, status(routeB, tokA), "route with no allowlist must accept idp-a token")
	assert.Equal(t, http.StatusOK, status(routeB, tokB), "route with no allowlist must accept idp-b token")
}

// TestExternalJWTBearer_UpstreamAuthorization asserts what the upstream
// receives in the Authorization header when Pomerium consumes a JWT bearer
// token: the caller's JWT is a credential for Pomerium, not for the upstream,
// so it must not be forwarded. A route may still send its own Authorization
// header to the upstream via set_request_headers.
func TestExternalJWTBearer_UpstreamAuthorization(t *testing.T) {
	const sub = "system:serviceaccount:default:my-sa"

	run := func(t *testing.T, globalJWT bool, path string, policy func(p *config.Policy)) string {
		t.Helper()

		env := testenv.New(t)
		idp, idpURL := configureJWTIdp(t, env, "demo-idp")
		if globalJWT {
			env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
				cfg.Options.BearerTokenFormat = nullable.From(configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT)
			}))
		}

		up := upstreams.HTTP(nil, upstreams.WithDisplayName("Echo"))
		up.Handle("/echo", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "upstream-auth=%q", r.Header.Get("Authorization"))
		})

		route := up.Route().
			From(env.SubdomainURL("api")).
			To(values.Bind(up.Addr(), func(addr string) string {
				return fmt.Sprintf("http://%s", addr)
			})).
			Policy(func(p *config.Policy) {
				var ppl config.PPLPolicy
				require.NoError(t, ppl.UnmarshalJSON([]byte(`{
					"allow": {"and": [{"claim/sub": "`+sub+`"}]}
				}`)))
				p.Policy = &ppl
				policy(p)
			})

		env.AddUpstream(up)
		env.Start()
		snippets.WaitStartupComplete(env)

		tok := idp.SignJWT(stdSAClaims(idpURL.Value(), sub, jwtBearerAudience, time.Now()))
		resp, err := up.Get(route,
			upstreams.Path(path),
			upstreams.Headers(map[string]string{"Authorization": "Bearer " + tok}),
		)
		require.NoError(t, err)
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%q", string(body))
		return string(body)
	}

	t.Run("route jwt format strips the caller's token", func(t *testing.T) {
		body := run(t, false, "/echo", func(p *config.Policy) { useJWTBearer(p) })
		assert.Equal(t, `upstream-auth=""`, body)
	})

	t.Run("global jwt format strips the caller's token", func(t *testing.T) {
		body := run(t, true, "/echo", func(*config.Policy) {})
		assert.Equal(t, `upstream-auth=""`, body)
	})

	t.Run("set_request_headers Authorization reaches the upstream", func(t *testing.T) {
		body := run(t, false, "/echo", func(p *config.Policy) {
			useJWTBearer(p)
			p.SetRequestHeaders = map[string]string{"Authorization": "Bearer upstream-api-key"}
		})
		assert.Equal(t, `upstream-auth="Bearer upstream-api-key"`, body)
	})

	t.Run("internal endpoints still see the caller's token", func(t *testing.T) {
		// With the global format, the proxy's own /.pomerium/ handlers
		// authenticate the caller from the same bearer token, so it must not
		// be stripped for them.
		body := run(t, true, endpoints.PathPomeriumUser, func(*config.Policy) {})
		assert.Contains(t, body, sub)
	})
}
