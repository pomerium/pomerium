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
)

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

// configureJWTIdp wires a mock OIDC issuer into Pomerium's
// jwt_identity_providers list and returns the IDP plus its URL.
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
		cfg.Options.JWTIdentityProviders = append(cfg.Options.JWTIdentityProviders, config.JWTIdentityProvider{
			Name:          idpName,
			Issuer:        idpURL.Value(),
			SupportedAlgs: []string{"ES256"}, // mockidp signs with ES256
		})
	}))

	return idp, idpURL
}

// TestExternalJWTBearer_HappyPath asserts a JWT-bearer authenticated request
// reaches the upstream when the route's accept_jwt_idps matches.
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
			p.AcceptJWTIdps = []config.JWTIdpAcceptance{
				{Name: "demo-idp", Audiences: []string{audience}},
			}
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
			p.AcceptJWTIdps = []config.JWTIdpAcceptance{
				{Name: "demo-idp", Audiences: []string{audience}},
			}
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
			"namespace": "platform",
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
			"namespace": "other",
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
			p.AcceptJWTIdps = []config.JWTIdpAcceptance{
				{Name: "demo-idp", Audiences: []string{"pomerium.example.com"}},
			}
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
// browser SSO. See change plan decision #1.
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
			p.AcceptJWTIdps = []config.JWTIdpAcceptance{
				{Name: "demo-idp", Audiences: []string{"pomerium.example.com"}},
			}
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

// TestExternalJWTBearer_CookieAndBearerCollision asserts that a request
// carrying both a Pomerium session cookie AND an Authorization: Bearer
// header is rejected with 400 (see change plan decision #6).
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
			p.AcceptJWTIdps = []config.JWTIdpAcceptance{
				{Name: "demo-idp", Audiences: []string{"pomerium.example.com"}},
			}
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
