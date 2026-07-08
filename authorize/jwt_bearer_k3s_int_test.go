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
// This test is opt-in: it is slow, requires Docker (~2GB RAM), and mutates the
// process-global OTel tracer, so it is skipped unless POMERIUM_K3S_INTEGRATION
// is set (running it in the same `go test` process as the other testenv tests
// would otherwise trip testenv's global-tracer guard). Run with:
//
//	POMERIUM_K3S_INTEGRATION=1 go test -count=1 -timeout=15m \
//	    -run TestExternalJWTBearer_K3s ./authorize/

package authorize_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tck3s "github.com/testcontainers/testcontainers-go/modules/k3s"
	"go.opentelemetry.io/otel"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
	authnv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/upstreams"
	"github.com/pomerium/pomerium/internal/testenv/values"
)

const (
	k3sImage          = "rancher/k3s:v1.31.0-k3s1"
	k3sDefaultIssuer  = "https://kubernetes.default.svc.cluster.local"
	pomeriumAudience  = "pomerium.example.com"
	testNamespace     = "default"
	testServiceAcct   = "pom-tester"
	tokenLifetimeSecs = 600
	idpName           = "k3s-test"
)

func TestExternalJWTBearer_K3s(t *testing.T) {
	if os.Getenv("POMERIUM_K3S_INTEGRATION") == "" {
		t.Skip("set POMERIUM_K3S_INTEGRATION=1 to run the k3s integration test (requires Docker)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	// 1. Spin up k3s.
	k3sCtr, err := tck3s.Run(ctx, k3sImage)
	require.NoError(t, err, "failed to start k3s testcontainer")
	t.Cleanup(func() {
		// testenv installs a panic-tracer as the global tracer provider.
		// The docker client (used by testcontainers' Terminate) runs an
		// otelhttp transport that goes through the global tracer — which
		// would panic. Swap to a noop tracer for the lifetime of Terminate.
		otel.SetTracerProvider(tracenoop.NewTracerProvider())
		_ = k3sCtr.Terminate(context.Background())
	})

	kubeConfigBytes, err := k3sCtr.GetKubeConfig(ctx)
	require.NoError(t, err)

	restCfg, err := clientcmd.RESTConfigFromKubeConfig(kubeConfigBytes)
	require.NoError(t, err)

	kc, err := kubernetes.NewForConfig(restCfg)
	require.NoError(t, err)

	// 2. Create a ServiceAccount we'll mint tokens for.
	_, err = kc.CoreV1().ServiceAccounts(testNamespace).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: testServiceAcct},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// 3. Fetch the cluster's JWKS bytes (we're authed as cluster-admin via
	//    the k3s kubeconfig, so reading the discovery endpoints is allowed).
	jwksBytes, err := kc.RESTClient().Get().AbsPath("/openid/v1/jwks").DoRaw(ctx)
	require.NoError(t, err, "failed to fetch cluster JWKS")
	require.NotEmpty(t, jwksBytes)
	t.Logf("fetched JWKS from k3s: %d bytes", len(jwksBytes))

	// 4. Local httptest server that mirrors the cluster's JWKS. Our named
	//    JWT IdP points its `jwks_url` at this server. The issuer string
	//    (in both the config and the JWT) remains the cluster's default
	//    `kubernetes.default.svc.cluster.local`.
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(jwksBytes)
	}))
	t.Cleanup(jwksSrv.Close)

	// 5. Mint a real ServiceAccount token with the Pomerium audience.
	tokReq := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			Audiences:         []string{pomeriumAudience},
			ExpirationSeconds: ptr[int64](tokenLifetimeSecs),
		},
	}
	tokResp, err := kc.CoreV1().ServiceAccounts(testNamespace).
		CreateToken(ctx, testServiceAcct, tokReq, metav1.CreateOptions{})
	require.NoError(t, err, "TokenRequest failed")
	saToken := tokResp.Status.Token
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
			require.NoError(t, ppl.UnmarshalJSON([]byte(fmt.Sprintf(`{
				"allow": {"and": [{"claim/sub": %q}]}
			}`, expectedSub))))
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
	tokReq2 := &authnv1.TokenRequest{
		Spec: authnv1.TokenRequestSpec{
			Audiences:         []string{"someone-else"},
			ExpirationSeconds: ptr[int64](tokenLifetimeSecs),
		},
	}
	tokResp2, err := kc.CoreV1().ServiceAccounts(testNamespace).
		CreateToken(ctx, testServiceAcct, tokReq2, metav1.CreateOptions{})
	require.NoError(t, err)

	resp2, err := up.Get(route,
		upstreams.Path("/echo"),
		upstreams.Headers(map[string]string{"Authorization": "Bearer " + tokResp2.Status.Token}),
	)
	require.NoError(t, err)
	defer resp2.Body.Close()
	io.ReadAll(resp2.Body)
	assert.NotEqual(t, http.StatusOK, resp2.StatusCode,
		"wrong-audience token must not be accepted")
}

func ptr[T any](v T) *T { return &v }
