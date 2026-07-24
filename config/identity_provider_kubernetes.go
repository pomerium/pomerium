package config

// Support for `issuer: kubernetes:///` — the identity provider is the API
// server of the Kubernetes cluster this Pomerium pod runs in. The real issuer
// (the `iss` claim ServiceAccount tokens carry) is discovered from the API
// server's OIDC discovery document at resolver-build time, and the JWKS is
// fetched from <API-URL>/openid/v1/jwks with an authenticating, CA-aware HTTP
// client: modern clusters (Kubernetes >= 1.34) reject anonymous JWKS requests,
// so both fetches carry the pod's ServiceAccount token.
//
// Scope: this mode targets clusters where the API server itself serves the
// JWKS (self-hosted issuer: kubeadm, k3s, OrbStack, ...). Clusters that
// publish their JWKS at a public external URL (some managed clouds) can keep
// using a plain issuer:/jwks_url: with anonymous discovery.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const (
	kubernetesIssuerScheme = "kubernetes"

	// Standard locations projected into every pod.
	kubernetesTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // standard projected file path, not a credential
	kubernetesCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	// Issuer discovery is a network call at config-load time. The in-cluster
	// API server is a hard dependency of the pod, so it is expected to answer
	// promptly; the timeout only bounds how long an unreachable API server can
	// stall config load before surfacing a clear error.
	kubernetesDiscoveryTimeout = 10 * time.Second
)

// parseKubernetesIssuer reports whether issuer uses the kubernetes:// scheme.
// apiHost is the optional authority (host[:port]) overriding the API server
// address; empty (kubernetes:///) means "use the standard pod environment".
func parseKubernetesIssuer(issuer string) (isK8s bool, apiHost string) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != kubernetesIssuerScheme {
		return false, ""
	}
	return true, u.Host
}

// kubernetesInClusterParams locates the in-cluster Kubernetes API. Production
// always uses defaultKubernetesInClusterParams; tests inject fake values via
// withKubernetesInClusterParams.
type kubernetesInClusterParams struct {
	apiURL    string // https base URL of the API server
	tokenFile string // pod ServiceAccount token
	caFile    string // cluster CA bundle
}

func defaultKubernetesInClusterParams(apiHost string) kubernetesInClusterParams {
	apiURL := "https://kubernetes.default.svc"
	if apiHost != "" {
		apiURL = "https://" + apiHost
	} else if host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT"); host != "" && port != "" {
		apiURL = "https://" + net.JoinHostPort(host, port)
	}
	return kubernetesInClusterParams{
		apiURL:    apiURL,
		tokenFile: kubernetesTokenFile,
		caFile:    kubernetesCAFile,
	}
}

// kubernetesAuthRoundTripper adds the pod's ServiceAccount bearer token to
// every request. The token is read from the file on each round-trip rather
// than cached: the kubelet rotates projected tokens, and a stale bearer would
// turn every JWKS refresh into a 401.
type kubernetesAuthRoundTripper struct {
	base      http.RoundTripper
	tokenFile string
}

func (rt *kubernetesAuthRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	tok, err := os.ReadFile(rt.tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read kubernetes serviceaccount token: %w", err)
	}
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(tok)))
	return rt.base.RoundTrip(req)
}

// newKubernetesHTTPClient builds the HTTP client used for the in-cluster
// discovery and JWKS fetches: TLS verified against the cluster CA,
// authenticated with the pod's ServiceAccount token.
func newKubernetesHTTPClient(p kubernetesInClusterParams) (*http.Client, error) {
	rootCAs, err := cryptutil.GetCertPool("", p.caFile)
	if err != nil {
		return nil, fmt.Errorf("load kubernetes cluster CA: %w", err)
	}
	transport := http.DefaultTransport.(interface{ Clone() *http.Transport }).Clone()
	// http.DefaultTransport may be config.NewHTTPTransport's transport (see
	// pkg/cmd/pomerium), whose DialTLSContext is pinned to the global CA pool
	// and takes precedence over TLSClientConfig.
	transport.DialTLSContext = nil
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    rootCAs,
		MinVersion: tls.VersionTLS12,
	}
	return &http.Client{Transport: &kubernetesAuthRoundTripper{
		base:      transport,
		tokenFile: p.tokenFile,
	}}, nil
}

// resolveKubernetesIssuer fetches the API server's OIDC discovery document and
// returns the real issuer (the `iss` claim ServiceAccount tokens carry) plus
// the JWKS URL. The JWKS URL is derived from the API server base URL, not the
// discovery document's jwks_uri: the advertised issuer host may not be
// routable from the pod, while <apiURL>/openid/v1/jwks always is.
func resolveKubernetesIssuer(ctx context.Context, client *http.Client, p kubernetesInClusterParams) (issuer, jwksURL string, err error) {
	ctx, cancel := context.WithTimeout(ctx, kubernetesDiscoveryTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.apiURL+"/.well-known/openid-configuration", nil)
	if err != nil {
		return "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("fetch kubernetes OIDC discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body) // drain so the connection can be reused
		return "", "", fmt.Errorf("fetch kubernetes OIDC discovery: %s returned %s", req.URL, resp.Status)
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&doc); err != nil {
		return "", "", fmt.Errorf("decode kubernetes OIDC discovery: %w", err)
	}
	if doc.Issuer == "" {
		return "", "", fmt.Errorf("kubernetes OIDC discovery document at %s has no issuer", req.URL)
	}
	return doc.Issuer, p.apiURL + "/openid/v1/jwks", nil
}

// identityProviderResolverOption customizes NewIdentityProviderResolver.
// Package-private: the only option is the test seam for in-cluster parameters.
type identityProviderResolverOption func(*identityProviderResolverConfig)

type identityProviderResolverConfig struct {
	kubernetesParams *kubernetesInClusterParams
}

// withKubernetesInClusterParams overrides the in-cluster API location so tests
// can point kubernetes:// providers at a fake API server.
func withKubernetesInClusterParams(p kubernetesInClusterParams) identityProviderResolverOption {
	return func(c *identityProviderResolverConfig) { c.kubernetesParams = &p }
}
