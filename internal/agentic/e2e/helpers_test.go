package e2e

import (
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/agentic"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/internal/testutil/mockidp"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

// The AS's endpoint paths, derived the same way the handler derives them, so a
// route these tests build always points where the AS actually serves.
var (
	runsPath    = agentic.RunsPath(agentic.DefaultPrefix)
	tokenPath   = agentic.TokenPath(agentic.DefaultPrefix)
	approvePath = agentic.ApprovePath(agentic.DefaultPrefix)
)

// noRedirect copies the cached route client (preserving its TLS trust) and
// disables redirect following, so deny responses surface as their real status
// instead of being followed to the sign-in page.
func noRedirect(c *http.Client) *http.Client {
	c2 := *c
	c2.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c2
}

// runTokenClient is noRedirect plus a dropped cookie jar, so the request carries
// only the run token — faithfully simulating a headless executor pod, which has
// no browser session cookie. A bearer-token route rejects a request that carries
// both a session cookie and a bearer (400), so a cookie jar left over from a
// prior browser SSO in the same test must not leak into a run-token call.
func runTokenClient(c *http.Client) *http.Client {
	c2 := *noRedirect(c)
	c2.Jar = nil
	return &c2
}

// bearer builds an Authorization header carrying the given token.
func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

// workloadJWT mints a workload token from idp with the standard registered
// claims, optionally carrying a kubernetes.io claim tree. It is the one place
// the tests describe what a projected token looks like.
func workloadJWT(idp *mockidp.IDP, issuer, sub string, issuedAt time.Time, k8s map[string]any) string {
	claims := map[string]any{
		"iss": issuer,
		"sub": sub,
		"aud": []string{workloadAudience},
		"exp": issuedAt.Add(time.Hour).Unix(),
		"iat": issuedAt.Unix(),
		"nbf": issuedAt.Unix(),
	}
	if k8s != nil {
		claims["kubernetes.io"] = k8s
	}
	return idp.SignJWT(claims)
}

// podClaims is the kubernetes.io claim tree a kubelet-projected token carries.
// executorSeal below is the same identity flattened, which is what makes the
// bind-time seal-match compare like for like.
func podClaims(serviceAccount, podName, podUID string) map[string]any {
	return map[string]any{
		"namespace":      "default",
		"serviceaccount": map[string]any{"name": serviceAccount},
		"pod":            map[string]any{"name": podName, "uid": podUID},
	}
}

// executorSeal is the attested identity subset a client pins a run to at create
// time (§12.8). Its keys/values must reproduce, key-for-key, the flattened
// claims the executor's own token carries (see the sidecar JWTs below), so the
// bind-time seal-match succeeds only for that one instance.
func executorSeal(serviceAccount, podName, podUID string) map[string]string {
	return map[string]string{
		"kubernetes.io.namespace":           "default",
		"kubernetes.io.serviceaccount.name": serviceAccount,
		"kubernetes.io.pod.name":            podName,
		"kubernetes.io.pod.uid":             podUID,
	}
}

// postJSON POSTs body (json-encoded) to path on route and decodes the JSON
// response body into a map. headers is optional.
func postJSON(t *testing.T, up upstreams.HTTPUpstream, route testenv.Route, path string, headers map[string]string, body any) (*http.Response, map[string]any) {
	t.Helper()
	// Machine callers are headless: no redirect following, no cookie jar. A
	// leftover browser cookie next to a bearer is rejected as a confused client,
	// and a sign-in redirect is not something a pod would ever follow.
	opts := []upstreams.RequestOption{
		upstreams.Path(path), upstreams.Body(body), upstreams.ClientHook(runTokenClient),
	}
	if headers != nil {
		opts = append(opts, upstreams.Headers(headers))
	}
	resp, err := up.Post(route, opts...)
	require.NoError(t, err)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp, out
}

// agenticRoutes are the three ordinary routes the authorization server sits
// behind. They share one host and split by path, because the three endpoints
// have three different callers with three different credentials — and it is
// these routes' policies, not the AS, that decide who may summon, exchange or
// approve.
type agenticRoutes struct {
	// summon carries POST /agentic/runs and GET /agentic/runs/{id}, so it is a
	// prefix route. The summoner authenticates with its own workload JWT.
	summon testenv.Route
	// token carries POST /agentic/token, an exact path so that nothing below it
	// can be reached under this policy. The executor authenticates with its
	// projected token.
	token testenv.Route
	// approve carries the consent page, GET and POST. A human authenticates with
	// a browser session.
	approve testenv.Route
}

// newAgenticRoutes builds the three routes in front of the AS's own listener.
// summonPolicy and exchangePolicy are the admin's statements about which
// workloads may create runs and which may exchange a token for one; approvePolicy
// gates the humans.
func newAgenticRoutes(
	t *testing.T,
	env testenv.Environment,
	idpName string,
	summonPolicy, exchangePolicy, approvePolicy string,
) agenticRoutes {
	t.Helper()

	// The AS listens on loopback only. Pointing routes at it is the only way it is
	// reachable at all — which is what makes the routes' policies load-bearing
	// rather than decorative.
	asAddr := values.Const("pomerium://agentic")
	host := env.SubdomainURL("agentic")

	// Built directly rather than through up.Route(), which pre-seeds the upstream's
	// own address as a destination and would leave each route load-balancing
	// between the echo server and the AS.
	asRoute := func(ppl string, edit func(*config.Policy)) testenv.Route {
		r := &testenv.PolicyRoute{}
		r.From(host).To(asAddr).PPL(ppl).Policy(edit)
		env.Add(r)
		return r
	}
	machineRoute := func(ppl string, edit func(*config.Policy)) testenv.Route {
		return asRoute(ppl, func(p *config.Policy) {
			// The route mints a session from the presented workload JWT, which is
			// what lets its policy read claim/... at all: PPL can only see a session.
			p.BearerTokenFormat = nullable.From(configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT)
			p.IdentityProviders = []string{idpName}
			edit(p)
		})
	}

	return agenticRoutes{
		summon: machineRoute(summonPolicy, func(p *config.Policy) {
			p.Prefix = runsPath
			// Without this Envoy rewrites Host to the upstream address and the AS
			// hands the caller an approval link pointing at its own loopback port.
			p.PreserveHostHeader = true
		}),
		token: machineRoute(exchangePolicy, func(p *config.Policy) {
			p.Path = tokenPath
		}),
		approve: asRoute(approvePolicy, func(p *config.Policy) {
			p.Path = approvePath
			// Without this Envoy strips X-Pomerium-Jwt-Assertion and every approval
			// 401s: the whole approve handler starts from that header.
			p.PassIdentityHeaders = new(true)
			p.PreserveHostHeader = true
			// Declaring the consent page an MCP client registers its host as a valid
			// redirect target, which is what lets a Connect round trip on an MCP
			// route's host return here.
			p.MCP = &config.MCP{Client: &config.MCPClient{}}
		}),
	}
}

// getRunStatus GETs the run-status endpoint for runID on the summon route with an
// optional workload JWT (omitted when jwt is ""), and decodes the JSON response.
func getRunStatus(t *testing.T, up upstreams.HTTPUpstream, route testenv.Route, jwt, runID string) (*http.Response, map[string]any) {
	t.Helper()
	opts := []upstreams.RequestOption{
		upstreams.Path(runsPath + "/" + runID), upstreams.ClientHook(runTokenClient),
	}
	if jwt != "" {
		opts = append(opts, upstreams.Headers(bearer(jwt)))
	}
	resp, err := up.Get(route, opts...)
	require.NoError(t, err)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp, out
}

// browsers gives each email its own cookie jar. The upstream helper caches one
// client per route, so without this two people approving on the one agentic host
// would share a browser session.
type browsers struct {
	jars map[string]http.CookieJar
}

func newBrowsers() *browsers { return &browsers{jars: map[string]http.CookieJar{}} }

func (b *browsers) as(email string) upstreams.RequestOption {
	return upstreams.ClientHook(func(c *http.Client) *http.Client {
		jar, ok := b.jars[email]
		if !ok {
			jar, _ = cookiejar.New(nil)
			b.jars[email] = jar
		}
		c2 := *c
		c2.Jar = jar
		return &c2
	})
}

// consentGet performs the authenticated browser GET of the consent page
// (following redirects through the SSO login) and returns status+body.
func (b *browsers) consentGet(t *testing.T, up upstreams.HTTPUpstream, route testenv.Route, email, runID string) (int, string) {
	t.Helper()
	resp, err := up.Get(route,
		upstreams.Path(approvePath),
		upstreams.Query(url.Values{"run_id": {runID}}),
		upstreams.AuthenticateAs(email),
		b.as(email),
	)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(body)
}

// approvePost submits the consent form as the signed-in browser user, with a
// url-encoded body, mirroring a real form submission.
func (b *browsers) approvePost(t *testing.T, up upstreams.HTTPUpstream, route testenv.Route, email, code string) (int, string) {
	t.Helper()
	resp, err := up.Post(route,
		upstreams.Path(approvePath),
		upstreams.AuthenticateAs(email),
		b.as(email),
		upstreams.Body("code="+url.QueryEscape(code)),
		upstreams.Headers(map[string]string{"Content-Type": "application/x-www-form-urlencoded"}),
	)
	require.NoError(t, err)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(body)
}

// codeFieldRE extracts the CSRF/approval code from a rendered consent page.
var codeFieldRE = regexp.MustCompile(`name="code" value="([^"]+)"`)

// extractApprovalCode pulls the hidden approval code out of a consent page. A
// browser decodes HTML entities when reading an attribute value (html/template
// escapes base64's '+' as &#43;), so mirror that before submitting the form.
func extractApprovalCode(t *testing.T, page string) string {
	t.Helper()
	m := codeFieldRE.FindStringSubmatch(page)
	require.Len(t, m, 2, "must be able to extract the approval code from the page")
	return html.UnescapeString(m[1])
}

// getWithToken GETs /echo on route with a bearer token, following no redirects,
// and returns the status code and body.
func getWithToken(t *testing.T, up upstreams.HTTPUpstream, route testenv.Route, token string) (int, string) {
	t.Helper()
	resp, err := up.Get(route,
		upstreams.Path("/echo"),
		upstreams.Headers(bearer(token)),
		upstreams.ClientHook(runTokenClient),
	)
	require.NoError(t, err)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b)
}
