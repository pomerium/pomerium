package config

// Support for `issuer: kubernetes:///`: the identity provider is the API server
// of the cluster this pod runs in.
//
// The issuer comes from the pod's own ServiceAccount token: its `iss` is
// --service-account-issuer[0], which is exactly the value the API server's OIDC
// discovery document advertises as `issuer`, so reading it locally costs nothing
// in fidelity. The keys come from <apiURL>/openid/v1/jwks, fetched lazily over a
// client pinned to the cluster CA and bearing that token, which the endpoint
// requires under the default RBAC. The discovery document is never fetched:
// `iss` is all we would read from it, and its jwks_uri we do not follow.
//
// Everything here is resolved lazily, on the first bearer token whose issuer no
// statically-configured provider claims — never at configuration load. A pod
// that has no projected token (or none yet) therefore costs this provider only,
// leaving the rest of the identity_providers map working, and it recovers on its
// own once the token appears instead of waiting for a configuration change.
//
// Consequences worth knowing:
//
//   - A cluster may accept several issuers (--service-account-issuer repeats;
//     the first signs, all validate). Only the first is matched here, so tokens
//     still held under a secondary issuer are rejected. An issuer migration
//     presents as a token no provider matches, which is exactly what triggers a
//     re-read of this pod's token, so it self-corrects within
//     kubernetesResolveInterval of the kubelet rotating that token.
//   - Because the key fetch is lazy, an endpoint the cluster denies (RBAC
//     hardened past the default binding) surfaces per request rather than at
//     configuration load, and go-oidc retries it per request — it caches keys but
//     not failures.
//
// A plain issuer:/jwks_url: pair is usually the better fit on the managed clouds:
// kubernetes:/// does work there — `iss` names their hosted issuer and the API
// server still serves the signing keys — but the hosted JWKS (EKS
// oidc.eks.<region>.amazonaws.com, GKE container.googleapis.com, AKS
// <region>.oic.prod-aks.azure.com) is reachable without the cluster CA or a
// ServiceAccount bearer.

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/identity/oidc/extjwt"
)

const (
	kubernetesIssuerScheme = "kubernetes"

	// Standard locations projected into every pod.
	kubernetesTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // standard projected file path, not a credential
	kubernetesCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	// kubernetesJWKSPath is the API server's own JWKS endpoint. OIDC Discovery
	// would have us follow the advertised jwks_uri instead, but that names an
	// endpoint for consumers outside the cluster (--service-account-jwks-uri),
	// whereas this client trusts only the cluster CA and carries the pod's token.
	// The API server's own endpoint stays authoritative even when that flag is set.
	kubernetesJWKSPath = "/openid/v1/jwks"
)

// parseKubernetesIssuer reports whether issuer uses the kubernetes:// scheme.
// apiHost is the optional authority (host[:port]) overriding the API server
// address; empty (kubernetes:///) means "use the standard pod environment".
//
// The authority names another address for THIS cluster's API server, not another
// cluster: the token and CA still come from the local pod, and kubeadm and k3s
// both default to the same issuer string, so `iss` would not tell two clusters
// apart. Any path or query is ignored.
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
	tok, err := readKubernetesToken(rt.tokenFile)
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+tok)
	return rt.base.RoundTrip(req)
}

// readKubernetesToken reads the pod's ServiceAccount token. Trailing whitespace
// is trimmed: the projected file ends in a newline, which neither a bearer header
// nor a JWT parser tolerates.
func readKubernetesToken(tokenFile string) (string, error) {
	tok, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("read kubernetes serviceaccount token: %w", err)
	}
	return strings.TrimSpace(string(tok)), nil
}

// newKubernetesHTTPClient builds the HTTP client used for the JWKS fetches: TLS
// verified against the cluster CA, authenticated with the pod's ServiceAccount
// token.
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

// kubernetesResolveInterval bounds how often a deferredKubernetesProvider
// re-reads the pod's ServiceAccount token. It is both the recovery latency for a
// provider whose token was unreadable and the staleness window on an issuer
// migration — measured from a request no provider could match, not from a
// configuration change.
const kubernetesResolveInterval = 10 * time.Second

// deferredKubernetesProvider is a `kubernetes:///` identity provider whose issuer
// is not known until the pod's own ServiceAccount token is read.
//
// That read is the only part of building the provider map that depends on the
// environment rather than on the configuration, and doing it eagerly made a pod
// without a projected token fail the entire map. Deferring it to the dispatch
// path — where extjwt already defers its JWKS fetch — keeps the build pure,
// contains the failure to this provider, and lets it recover without a
// configuration change.
//
// resolve runs only when no statically-configured provider claims a token's
// issuer. Once resolved, the steady state is a single atomic load: a cluster
// whose tokens verify normally re-reads the pod's token only every
// kubernetesResolveInterval, and never blocks a request behind the read.
type deferredKubernetesProvider struct {
	name      string
	audiences []string // cloned at construction; shared by every resolution
	algs      []string
	params    kubernetesInClusterParams
	timeNow   func() time.Time // never nil; see identityProviderResolverConfig.clock

	// current is the last attempt's outcome, read without the lock on the fast
	// path. mu serializes only the attempts that replace it.
	current atomic.Pointer[kubernetesResolution]
	mu      sync.Mutex
}

// kubernetesResolution is the immutable outcome of one resolution attempt: the
// verification context if there is a usable one, why there is not, and when the
// next attempt becomes due. Published whole so a reader never sees a half-updated
// provider and needs no lock to use one.
type kubernetesResolution struct {
	rp   resolvedIdentityProvider // zero Provider means "no verifier"
	err  error                    // why this attempt failed, nil on success
	next time.Time                // when the next attempt becomes due
}

// issuer is the issuer this resolution verifies for, or "" if it has none.
func (res *kubernetesResolution) issuer() string {
	if res.rp.Provider == nil {
		return ""
	}
	return res.rp.Provider.Issuer()
}

// resolve returns this provider's current resolution, re-reading the pod's
// ServiceAccount token at most once per kubernetesResolveInterval.
func (d *deferredKubernetesProvider) resolve(ctx context.Context) *kubernetesResolution {
	if res := d.current.Load(); res != nil && d.timeNow().Before(res.next) {
		return res
	}
	return d.refresh(ctx)
}

// refresh re-reads the token and publishes the outcome, reporting it to health
// and the log. It is the only place this provider's state changes.
func (d *deferredKubernetesProvider) refresh(ctx context.Context) *kubernetesResolution {
	d.mu.Lock()
	defer d.mu.Unlock()

	now := d.timeNow()
	previous := d.current.Load()
	// Another request may have refreshed while this one waited for the lock.
	if previous != nil && now.Before(previous.next) {
		return previous
	}

	res := &kubernetesResolution{next: now.Add(kubernetesResolveInterval)}
	if previous != nil {
		// A failed attempt keeps the last good verifier rather than dropping it: the
		// kubelet replaces the token file atomically, so a read that fails is a
		// transient condition, and rejecting every token over it would trade a
		// recoverable gap for an outage.
		res.rp = previous.rp
	}

	rp, err := d.reload(ctx, res.rp)
	if err != nil {
		res.err = fmt.Errorf("identity_providers[%s]: %w", d.name, err)
		health.ReportError(health.IdentityProvider(d.name), res.err)
		log.Ctx(ctx).Error().Err(res.err).
			Str("provider", d.name).
			Msg("config: identity_providers: kubernetes provider unavailable; " +
				"tokens issued by this cluster will be rejected, other providers are unaffected")
	} else {
		res.rp = rp
		health.ReportRunning(health.IdentityProvider(d.name))
	}

	d.current.Store(res)
	return res
}

// reload reads the issuer the pod's token names and returns the verification
// context for it, reusing prev's verifier when the issuer has not changed so the
// warm JWKS cache behind it survives.
func (d *deferredKubernetesProvider) reload(ctx context.Context, prev resolvedIdentityProvider) (resolvedIdentityProvider, error) {
	issuer, err := kubernetesIssuerFromToken(d.params.tokenFile)
	if err != nil {
		return resolvedIdentityProvider{}, err
	}
	if prev.Provider != nil && prev.Provider.Issuer() == issuer {
		return prev, nil
	}
	// The client is rebuilt with the verifier: it pins the cluster CA, which may
	// have rotated alongside the issuer.
	client, err := newKubernetesHTTPClient(d.params)
	if err != nil {
		return resolvedIdentityProvider{}, err
	}
	jwksURL := d.params.apiURL + kubernetesJWKSPath
	p, err := extjwt.New(extjwt.Config{
		Issuer:        issuer,
		JWKSURL:       jwksURL,
		SupportedAlgs: d.algs,
		HTTPClient:    client,
	})
	if err != nil {
		return resolvedIdentityProvider{}, err
	}
	log.Ctx(ctx).Debug().
		Str("provider", d.name).
		Str("issuer", issuer).
		Str("jwks_url", jwksURL).
		Msg("config: identity_providers: resolved in-cluster kubernetes provider")
	return resolvedIdentityProvider{
		Name:      d.name,
		Audiences: d.audiences,
		Provider:  p,
	}, nil
}

// kubernetesIssuerFromToken reads the `iss` claim of the pod's own ServiceAccount
// token. The signature is not checked and need not be: the value only decides
// which tokens this provider is offered and what `iss` the verifier then demands,
// so a wrong one rejects tokens rather than accepting them.
//
// The issuer must be a URL, which rejects a legacy non-projected token (issuer
// `kubernetes/serviceaccount`) at load rather than on every verification. A
// cluster whose --service-account-issuer is not a URL fails the same way, and
// serves no JWKS either.
func kubernetesIssuerFromToken(tokenFile string) (string, error) {
	tok, err := readKubernetesToken(tokenFile)
	if err != nil {
		return "", err
	}
	issuer, err := unverifiedIssuer(tok)
	if err != nil {
		return "", fmt.Errorf("read issuer from kubernetes serviceaccount token %s: %w", tokenFile, err)
	}
	if _, err := urlutil.ParseAndValidateURL(issuer); err != nil {
		return "", fmt.Errorf("kubernetes serviceaccount token %s has issuer %q: %w; "+
			"this needs a projected (bound) token and a cluster whose --service-account-issuer is a URL",
			tokenFile, issuer, err)
	}
	return issuer, nil
}

// identityProviderResolverOption customizes newIdentityProviderResolver.
// Package-private: the only option is the test seam for in-cluster parameters.
type identityProviderResolverOption func(*identityProviderResolverConfig)

type identityProviderResolverConfig struct {
	kubernetesParams *kubernetesInClusterParams
	timeNow          func() time.Time
}

// clock is the configured clock, or time.Now.
func (c identityProviderResolverConfig) clock() func() time.Time {
	if c.timeNow != nil {
		return c.timeNow
	}
	return time.Now
}

// withKubernetesInClusterParams overrides the in-cluster API location and token
// path so tests can point kubernetes:// providers at a fake API server.
func withKubernetesInClusterParams(p kubernetesInClusterParams) identityProviderResolverOption {
	return func(c *identityProviderResolverConfig) { c.kubernetesParams = &p }
}

// withIdentityProviderTimeNow overrides the clock the kubernetes:// providers
// measure kubernetesResolveInterval against, so tests can cross it without
// sleeping.
func withIdentityProviderTimeNow(fn func() time.Time) identityProviderResolverOption {
	return func(c *identityProviderResolverConfig) { c.timeNow = fn }
}
