package authorize_test

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/volatiletech/null/v9"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/scenarios"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/nullable"
)

// echoCredentialHeaders reports the credential-bearing headers the upstream
// received.
func echoCredentialHeaders(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "authorization=%q x-pomerium-authorization=%q",
		r.Header.Get("Authorization"), r.Header.Get("X-Pomerium-Authorization"))
}

// getWithHeaders sends a GET to the route with the given headers as its only
// credential (no login), returning the status and the upstream's echo.
func getWithHeaders(t *testing.T, up upstreams.HTTPUpstream, route testenv.Route, headers map[string]string) (int, string) {
	t.Helper()

	resp, err := up.Get(route, upstreams.Headers(headers))
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, string(body)
}

// TestUpstreamCredentials_PomeriumJWT asserts that a Pomerium-issued JWT is
// never forwarded to the upstream, whichever of the supported header forms
// carries it: it is a credential for Pomerium, and an upstream holding it
// could replay it against any other route the user can reach.
func TestUpstreamCredentials_PomeriumJWT(t *testing.T) {
	env := testenv.New(t)
	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "user@example.com"}}))

	up := upstreams.HTTP(nil, upstreams.WithDisplayName("Echo"))
	up.Handle("/", echoCredentialHeaders)
	route := up.Route().
		From(env.SubdomainURL("echo")).
		Policy(func(p *config.Policy) { p.AllowAnyAuthenticatedUser = true })
	env.AddUpstream(up)

	env.Start()
	snippets.WaitStartupComplete(env)

	sa := &user.ServiceAccount{Id: "upstream-creds-sa", UserId: "user@example.com"}
	_, err := user.PutServiceAccount(t.Context(), env.NewDataBrokerServiceClient(), sa)
	require.NoError(t, err)
	jwt, err := cryptutil.SignServiceAccount(env.SharedSecret(), sa.Id, sa.UserId, time.Now(), null.Time{})
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		headers map[string]string
	}{
		{"Authorization: Pomerium", map[string]string{"Authorization": "Pomerium " + jwt}},
		{"Authorization: Bearer Pomerium-", map[string]string{"Authorization": "Bearer Pomerium-" + jwt}},
		{"X-Pomerium-Authorization", map[string]string{"X-Pomerium-Authorization": jwt}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, body := getWithHeaders(t, up, route, tc.headers)
			require.Equal(t, http.StatusOK, status, "body=%q", body)
			assert.Equal(t, `authorization="" x-pomerium-authorization=""`, body,
				"the caller's Pomerium JWT must not reach the upstream")
		})
	}
}

// TestUpstreamCredentials_EmptySetRequestHeader asserts that a
// set_request_headers Authorization that renders empty still replaces the
// caller's Pomerium JWT, rather than the header being removed.
func TestUpstreamCredentials_EmptySetRequestHeader(t *testing.T) {
	env := testenv.New(t)
	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "user@example.com"}}))

	up := upstreams.HTTP(nil, upstreams.WithDisplayName("Echo"))
	up.Handle("/", func(w http.ResponseWriter, r *http.Request) {
		vs, ok := r.Header["Authorization"]
		fmt.Fprintf(w, "authorization=%q present=%t", vs, ok)
	})
	route := up.Route().
		From(env.SubdomainURL("echo")).
		Policy(func(p *config.Policy) {
			p.AllowAnyAuthenticatedUser = true
			// a service account has no IdP access token, so this renders empty
			p.SetRequestHeaders = map[string]string{"Authorization": "${pomerium.access_token}"}
		})
	env.AddUpstream(up)

	env.Start()
	snippets.WaitStartupComplete(env)

	sa := &user.ServiceAccount{Id: "upstream-creds-sa", UserId: "user@example.com"}
	_, err := user.PutServiceAccount(t.Context(), env.NewDataBrokerServiceClient(), sa)
	require.NoError(t, err)
	jwt, err := cryptutil.SignServiceAccount(env.SharedSecret(), sa.Id, sa.UserId, time.Now(), null.Time{})
	require.NoError(t, err)

	status, body := getWithHeaders(t, up, route, map[string]string{"Authorization": "Pomerium " + jwt})
	require.Equal(t, http.StatusOK, status, "body=%q", body)
	assert.Equal(t, `authorization=[""] present=true`, body)
}

// TestUpstreamCredentials_IDPTokens asserts that on routes where Pomerium
// authenticates the caller from an IdP access or identity token in the
// Authorization header, that token is not forwarded to the upstream.
func TestUpstreamCredentials_IDPTokens(t *testing.T) {
	env := testenv.New(t)
	env.Add(scenarios.NewIDP([]*scenarios.User{{Email: "user@example.com"}}))

	// A cookie-SSO route that hands the session's IdP tokens to its upstream,
	// so the test can obtain real tokens to present as bearers.
	tokens := upstreams.HTTP(nil, upstreams.WithDisplayName("Tokens"))
	tokens.Handle("/access", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("X-Access-Token")))
	})
	tokens.Handle("/identity", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("X-Identity-Token")))
	})
	tokensRoute := tokens.Route().
		From(env.SubdomainURL("tokens")).
		Policy(func(p *config.Policy) {
			p.AllowAnyAuthenticatedUser = true
			p.SetRequestHeaders = map[string]string{
				"X-Access-Token":   "${pomerium.access_token}",
				"X-Identity-Token": "${pomerium.id_token}",
			}
		})
	env.AddUpstream(tokens)

	up := upstreams.HTTP(nil, upstreams.WithDisplayName("Echo"))
	up.Handle("/", echoCredentialHeaders)
	route := func(subdomain string, format configpb.BearerTokenFormat) testenv.Route {
		return up.Route().
			From(env.SubdomainURL(subdomain)).
			Policy(func(p *config.Policy) {
				p.AllowAnyAuthenticatedUser = true
				p.BearerTokenFormat = nullable.From(format)
			})
	}
	accessRoute := route("access", configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_ACCESS_TOKEN)
	identityRoute := route("identity", configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_IDP_IDENTITY_TOKEN)
	env.AddUpstream(up)

	env.Start()
	snippets.WaitStartupComplete(env)

	getToken := func(t *testing.T, path string) string {
		t.Helper()
		resp, err := tokens.Get(tokensRoute, upstreams.AuthenticateAs("user@example.com"), upstreams.Path(path))
		require.NoError(t, err)
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "body=%q", string(body))
		require.NotEmpty(t, body, "no %s token in the session", path)
		return string(body)
	}

	for _, tc := range []struct {
		name  string
		route testenv.Route
		path  string
	}{
		{"idp_access_token", accessRoute, "/access"},
		{"idp_identity_token", identityRoute, "/identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := getToken(t, tc.path)
			status, body := getWithHeaders(t, up, tc.route, map[string]string{"Authorization": "Bearer " + token})
			require.Equal(t, http.StatusOK, status, "body=%q", body)
			assert.Equal(t, `authorization="" x-pomerium-authorization=""`, body,
				"the caller's IdP token must not reach the upstream")
		})
	}
}
