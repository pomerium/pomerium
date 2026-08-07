// Package authorize_test contains the extended Kubernetes integration test
// for the external-JWT identity provider. It spins up a real k3s cluster via
// testcontainers, mints a real ServiceAccount token through the apiserver's
// TokenRequest API, and verifies that an in-process Pomerium (driven by
// testenv) accepts that token end-to-end via bearer_token_format: jwt + a named
// entry in identity_providers (with per-provider audiences).
//
// Why this test exists:
//   - It exercises the JWKSURL override path (the default k3s issuer
//     `https://kubernetes.default.svc.cluster.local` is not externally
//     routable; we point the named provider at a local proxy serving the
//     real cluster JWKS bytes instead of doing OIDC discovery).
//   - It uses a real cluster-signed JWT — the same kind a pod would mount via
//     a `projected` SA-token volume in production.
//   - It demonstrates the Pomerium-specific audience scheme: only tokens
//     minted with audience "pomerium.example.com" pass.
//
// The cluster is driven through the kubectl binary inside the k3s container
// (see the kubectl helper below) rather than through k8s.io/client-go. That is
// deliberate: Pomerium's own Kubernetes support needs no Kubernetes client
// libraries, and the testcontainers k3s module does not import them either, so
// keeping this test client-free keeps k8s.io/* out of the module's dependency
// graph entirely — nothing to bump, scan, or compile for the sake of one
// skipped test.
//
// This test must run in isolation: it is slow, requires Docker (~2GB RAM), and
// mutates the process-global OTel tracer, so running it in the same `go test`
// process as the other testenv-based tests trips testenv's global-tracer panic
// guard. It is gated behind a per-test env var named after the test
// (RUN_<test name>), so it is skipped by default and never runs alongside a
// sibling e2e test. Run it via its dedicated Makefile target, which sets the
// env var and isolates it in its own process:
//
//	make test-e2e-k3s
//
// or directly:
//
//	RUN_TestExternalJWTBearer_K3s=1 go test -timeout=15m \
//	    -run '^TestExternalJWTBearer_K3s$' ./authorize/

package authorize_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	tck3s "github.com/testcontainers/testcontainers-go/modules/k3s"
	oteltrace "go.opentelemetry.io/otel/trace"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

const (
	// k3sImage is pinned rather than derived: the cluster is driven through the
	// container's own kubectl, so there is no k8s.io/* module version to read it
	// from.
	k3sImage = "rancher/k3s:v1.36.0-k3s1"

	k3sDefaultIssuer = "https://kubernetes.default.svc.cluster.local"
	pomeriumAudience = "pomerium.example.com"
	testNamespace    = "default"
	testServiceAcct  = "pom-tester"
	idpName          = "k3s-test"
)

// gateExclusiveIntegrationTest skips t unless an env var named after the test
// (RUN_<test name>) is set. Use it for heavyweight, non-hermetic tests that
// must run on their own — e.g. this one mutates the process-global OTel tracer
// and would trip testenv's global-tracer guard if run alongside other tests.
// The per-test env var keeps the gate granular: enabling one exclusive test
// never enables another.
func gateExclusiveIntegrationTest(t *testing.T) {
	t.Helper()
	envVar := "RUN_" + t.Name()
	if os.Getenv(envVar) == "" {
		t.Skipf("skipping %s: run it in isolation with %s=1 go test -run '^%s$' ./authorize/",
			t.Name(), envVar, t.Name())
	}
}

// dockerContext returns ctx carrying a valid noop span, which keeps the docker
// client's otelhttp transport off the global tracer provider — testenv installs
// one that panics on use. This is the same guard internal/testutil's container
// helpers use; without it any docker call made after testenv.New panics.
func dockerContext(ctx context.Context) context.Context {
	return oteltrace.ContextWithSpan(ctx, trace.ValidNoopSpan{})
}

// kubectl runs kubectl inside the k3s container and returns its stdout,
// failing the test if it cannot be run or exits non-zero. The k3s image ships
// kubectl at /bin/kubectl, already pointed at the cluster it serves, so this
// needs neither a kubeconfig on the host nor a Kubernetes client library.
func kubectl(ctx context.Context, t *testing.T, ctr *tck3s.K3sContainer, args ...string) string {
	t.Helper()
	// Multiplexed demuxes docker's stream framing; without it the output is
	// interleaved with per-frame headers.
	code, r, err := ctr.Exec(dockerContext(ctx), append([]string{"kubectl"}, args...), tcexec.Multiplexed())
	require.NoErrorf(t, err, "kubectl %v", args)
	out, err := io.ReadAll(r)
	require.NoErrorf(t, err, "reading output of kubectl %v", args)
	require.Zerof(t, code, "kubectl %v failed: %s", args, out)
	return strings.TrimSpace(string(out))
}

func TestExternalJWTBearer_K3s(t *testing.T) {
	gateExclusiveIntegrationTest(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// 1. Spin up k3s.
	k3sCtr, err := tck3s.Run(dockerContext(ctx), k3sImage)
	require.NoError(t, err, "failed to start k3s testcontainer")
	t.Cleanup(func() {
		// Not ctx: it may already be cancelled by the time cleanup runs.
		_ = k3sCtr.Terminate(dockerContext(context.Background()))
	})

	// 2. Create a ServiceAccount we'll mint tokens for.
	kubectl(ctx, t, k3sCtr, "create", "serviceaccount", testServiceAcct, "-n", testNamespace)

	// 3. Fetch the cluster's JWKS bytes (kubectl in the container is authed as
	//    cluster-admin, so reading the discovery endpoints is allowed).
	jwks := kubectl(ctx, t, k3sCtr, "get", "--raw", "/openid/v1/jwks")
	require.NotEmpty(t, jwks)
	t.Logf("fetched JWKS from k3s: %d bytes", len(jwks))

	// 4. Local httptest server that mirrors the cluster's JWKS. Our named
	//    JWT IdP points its `jwks_url` at this server. The issuer string
	//    (in both the config and the JWT) remains the cluster's default
	//    `kubernetes.default.svc.cluster.local`.
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = io.WriteString(w, jwks)
	}))
	t.Cleanup(jwksSrv.Close)

	// 5. Mint a real ServiceAccount token with the Pomerium audience.
	saToken := kubectl(ctx, t, k3sCtr, "create", "token", testServiceAcct,
		"-n", testNamespace, "--audience="+pomeriumAudience, "--duration=10m")
	require.NotEmpty(t, saToken)

	// 6. Stand up Pomerium with a named JWT IdP and a route that accepts it.
	env := testenv.New(t)

	env.Add(testenv.ModifierFunc(func(_ context.Context, cfg *config.Config) {
		if cfg.Options.IdentityProviders == nil {
			cfg.Options.IdentityProviders = map[string]config.IdentityProvider{}
		}
		cfg.Options.IdentityProviders[idpName] = config.IdentityProvider{
			Issuer:        k3sDefaultIssuer,
			JWKSURL:       jwksSrv.URL,
			Audiences:     []string{pomeriumAudience},
			SupportedAlgs: []string{"RS256"}, // k3s default signing algorithm
		}
	}))

	up := upstreams.HTTP(nil, upstreams.WithDisplayName("EchoK3s"))
	up.Handle("/echo", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	expectedSub := fmt.Sprintf("system:serviceaccount:%s:%s", testNamespace, testServiceAcct)
	route := up.Route().
		From(env.SubdomainURL("api-k3s")).
		To(values.Bind(up.Addr(), func(addr string) string {
			return fmt.Sprintf("http://%s", addr)
		})).
		Policy(func(p *config.Policy) {
			useJWTBearer(p, idpName)
			var ppl config.PPLPolicy
			require.NoError(t, ppl.UnmarshalJSON(fmt.Appendf(nil, `{
				"allow": {"and": [{"claim/sub": %q}]}
			}`, expectedSub)))
			p.Policy = &ppl
		})
	env.AddUpstream(up)

	env.Start()
	snippets.WaitStartupComplete(env)

	// 7. Send a request with the real k8s-issued JWT.
	resp, err := up.Get(route,
		upstreams.Path("/echo"),
		upstreams.Headers(map[string]string{"Authorization": "Bearer " + saToken}),
	)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode,
		"real k8s SA token should be accepted; got %d body=%q", resp.StatusCode, string(body))
	assert.Contains(t, string(body), "ok")

	// 8. Negative case: a token minted with a different audience must NOT be
	//    accepted, even though it's signed by the same cluster.
	otherAudToken := kubectl(ctx, t, k3sCtr, "create", "token", testServiceAcct,
		"-n", testNamespace, "--audience=someone-else", "--duration=10m")
	require.NotEmpty(t, otherAudToken)

	resp2, err := up.Get(route,
		upstreams.Path("/echo"),
		upstreams.Headers(map[string]string{"Authorization": "Bearer " + otherAudToken}),
	)
	require.NoError(t, err)
	defer resp2.Body.Close()
	io.ReadAll(resp2.Body)
	assert.NotEqual(t, http.StatusOK, resp2.StatusCode,
		"wrong-audience token must not be accepted")
}
