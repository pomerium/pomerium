package config

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/identity/oidc/extjwt"
)

// IdentityProvider declares an additional identity provider. Today it is
// usable only to verify JWT bearer tokens issued by non-interactive workloads
// (Kubernetes projected service-account tokens, GitHub Actions OIDC, SPIFFE
// JWT-SVIDs, …) on routes whose BearerTokenFormat is BEARER_TOKEN_FORMAT_JWT.
// It does not replace the interactive SSO identity provider (the flat idp_*
// options).
//
// Providers are declared as a map on Options; the map key is the provider
// name, referenced from Policy.IdentityProviders. Audience binding is
// per-provider (Audiences). Authorization on the verified claims is left to
// PPL (claim/...).
type IdentityProvider struct {
	// Issuer is the `iss` claim tokens must carry. Required, and unique across
	// providers. Used both to select the matching provider for an incoming
	// token and (with OIDC discovery) to fetch the signing keys.
	//
	// The special value `kubernetes:///` selects the API server of the
	// Kubernetes cluster Pomerium runs in: the real issuer and JWKS URL are
	// discovered from the standard in-cluster pod environment, and the fetches
	// are authenticated with the pod's ServiceAccount token (see
	// identity_provider_kubernetes.go).
	Issuer string `mapstructure:"issuer" yaml:"issuer"`
	// JWKSURL is an optional explicit JWKS URL. When set, OIDC discovery is
	// skipped — keys are fetched directly from this URL. Useful when the issuer
	// URL is not externally routable (e.g. Kubernetes'
	// `https://kubernetes.default.svc.cluster.local`).
	JWKSURL string `mapstructure:"jwks_url" yaml:"jwks_url,omitempty"`
	// SupportedAlgs is the JWT signing algorithms allowlist. When empty,
	// defaults to {RS256, ES256, EdDSA}. `none` and HMAC (HS*) algorithms are
	// rejected by Validate.
	SupportedAlgs []string `mapstructure:"supported_algs" yaml:"supported_algs,omitempty"`
	// Audiences accepted on tokens from this provider. Required and non-empty:
	// at least one must intersect the token's `aud` claim. Fail-closed — an
	// empty set rejects all tokens.
	Audiences []string `mapstructure:"audiences" yaml:"audiences"`
}

// DefaultJWTSupportedAlgs is used when an IdentityProvider does not specify
// SupportedAlgs. Avoids the go-oidc default of "RS256 only" so that ES256
// (SPIFFE, some EKS configurations) and EdDSA-signed tokens are accepted out
// of the box.
var DefaultJWTSupportedAlgs = []string{"RS256", "ES256", "EdDSA"}

// validSigningAlgs is the allowlist of asymmetric JWT signing algorithms that
// may appear in IdentityProvider.SupportedAlgs. Symmetric (HS*) and `none` are
// deliberately excluded: a shared-secret or unsigned token has no place in
// bearer-token verification against a public JWKS (RFC 8725 §2.1, §3.2).
var validSigningAlgs = map[string]struct{}{
	"RS256": {}, "RS384": {}, "RS512": {},
	"PS256": {}, "PS384": {}, "PS512": {},
	"ES256": {}, "ES384": {}, "ES512": {},
	"EdDSA": {},
}

// Validate checks that the IdentityProvider is well-formed.
func (p IdentityProvider) Validate() error {
	if p.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	// The issuer must be an absolute URL: it selects the provider for an
	// incoming token (exact `iss` match) and, on the discovery path, is where
	// the discovery document and JWKS are fetched. A bare/relative string like
	// "foo" is a config error, not a runtime discovery failure.
	iu, err := url.Parse(p.Issuer)
	if err != nil {
		return fmt.Errorf("invalid issuer URL %q: %w", p.Issuer, err)
	}
	if iu.Scheme == kubernetesIssuerScheme {
		// kubernetes:// selects the in-cluster API server as the issuer; the
		// real issuer URL and JWKS URL are discovered from the pod environment
		// at resolver-build time, so there is no https/host to validate here.
		// An explicit jwks_url would be silently ignored on that path — reject
		// the combination instead.
		if p.JWKSURL != "" {
			return fmt.Errorf("jwks_url must not be set with a kubernetes:// issuer (the JWKS URL is discovered in-cluster)")
		}
	} else {
		if !iu.IsAbs() || iu.Host == "" {
			return fmt.Errorf("issuer %q must be an absolute URL (scheme://host)", p.Issuer)
		}
		// Signing keys must not be fetched over plaintext HTTP: an on-path attacker
		// could substitute the JWKS and forge acceptable tokens. Require https,
		// permitting http only for loopback (local development / tests).
		if !isSecureKeyURL(iu) {
			return fmt.Errorf("issuer %q must use https (http allowed only for loopback)", p.Issuer)
		}
		if p.JWKSURL != "" {
			u, err := url.Parse(p.JWKSURL)
			if err != nil {
				return fmt.Errorf("invalid jwks_url: %w", err)
			}
			if !u.IsAbs() || u.Host == "" || !isSecureKeyURL(u) {
				return fmt.Errorf("jwks_url must be an https URL (http allowed only for loopback)")
			}
		}
	}
	if len(p.Audiences) == 0 {
		return fmt.Errorf("at least one audience is required")
	}
	for _, alg := range p.SupportedAlgs {
		if _, ok := validSigningAlgs[alg]; !ok {
			return fmt.Errorf("unsupported signing algorithm %q "+
				"(allowed: RS/PS/ES 256/384/512, EdDSA)", alg)
		}
	}
	return nil
}

// isSecureKeyURL reports whether u is safe to fetch signing-key material from:
// https always, or http only when the host is loopback (local dev / tests).
func isSecureKeyURL(u *url.URL) bool {
	if u.Scheme == "https" {
		return true
	}
	return u.Scheme == "http" && isLoopbackHost(u.Hostname())
}

// isLoopbackHost reports whether host is a loopback address or name
// (127.0.0.0/8, ::1, localhost, *.localhost).
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	h := strings.ToLower(host)
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// EffectiveSupportedAlgs returns p.SupportedAlgs or the default allowlist.
func (p IdentityProvider) EffectiveSupportedAlgs() []string {
	if len(p.SupportedAlgs) > 0 {
		return slices.Clone(p.SupportedAlgs)
	}
	return slices.Clone(DefaultJWTSupportedAlgs)
}

// validateProviderName rejects names that can't be safely used to namespace a
// user id ("<provider-name>/<sub>"). Forbidding "/" keeps that composition
// injective — provider names contain no "/", so the first "/" always splits
// provider from sub — preventing distinct (provider, sub) pairs from collapsing
// onto one user id.
//
// Names must also be lowercase: viper lowercases map keys when loading the
// config file, but route-level references (Route.identity_providers) are list
// values and keep the operator's casing — a mixed-case name could therefore
// never be referenced from a route. Rejecting it up front beats a confusing
// "unknown identity provider" error at the reference site.
func validateProviderName(name string) error {
	if name == "" {
		return fmt.Errorf("identity_providers: provider name must not be empty")
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("identity_providers[%s]: provider name must not contain '/'", name)
	}
	if name != strings.ToLower(name) {
		return fmt.Errorf("identity_providers[%s]: provider name must be lowercase", name)
	}
	return nil
}

// validateIdentityProviders checks the identity_providers configuration:
// every provider is well-formed, issuers are unique across providers, and
// every route that resolves to BEARER_TOKEN_FORMAT_JWT has at least one usable
// provider and references only providers that exist. A non-JWT route must not
// set identity_providers.
func (o *Options) validateIdentityProviders() error {
	seenIssuer := make(map[string]string, len(o.IdentityProviders)) // issuer -> provider name
	// Iterate in sorted-name order so validation errors (e.g. which two
	// providers share an issuer) are deterministic across runs.
	for _, name := range slices.Sorted(maps.Keys(o.IdentityProviders)) {
		ip := o.IdentityProviders[name]
		if err := validateProviderName(name); err != nil {
			return fmt.Errorf("config: %w", err)
		}
		if err := ip.Validate(); err != nil {
			return fmt.Errorf("config: identity_providers[%s]: %w", name, err)
		}
		if other, dup := seenIssuer[ip.Issuer]; dup {
			return fmt.Errorf("config: identity_providers: issuer %q used by both %q and %q",
				ip.Issuer, other, name)
		}
		seenIssuer[ip.Issuer] = name
	}

	globalFormat := configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_UNKNOWN
	if o.BearerTokenFormat.IsSet {
		globalFormat = o.BearerTokenFormat.Value
	}
	isJWT := func(p *Policy) bool {
		if p.BearerTokenFormat.IsSet {
			return p.BearerTokenFormat.Value == configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT
		}
		return globalFormat == configpb.BearerTokenFormat_BEARER_TOKEN_FORMAT_JWT
	}

	for p := range o.GetAllPolicies() {
		if !isJWT(p) {
			if len(p.IdentityProviders) > 0 {
				return fmt.Errorf("config: identity_providers is only valid on routes with "+
					"bearer_token_format=jwt (route %q)", p.String())
			}
			continue
		}
		if len(o.IdentityProviders) == 0 {
			return fmt.Errorf("config: bearer_token_format=jwt requires at least one "+
				"identity_providers entry (route %q)", p.String())
		}
		for _, name := range p.IdentityProviders {
			if _, ok := o.IdentityProviders[name]; !ok {
				if _, ok := o.IdentityProviders[strings.ToLower(name)]; ok {
					return fmt.Errorf("config: route %q references unknown identity provider %q (provider names are lowercase: did you mean %q?)",
						p.String(), name, strings.ToLower(name))
				}
				return fmt.Errorf("config: route %q references unknown identity provider %q",
					p.String(), name)
			}
		}
	}
	return nil
}

// identityProvidersToProto converts the Options map to its proto form.
func identityProvidersToProto(src map[string]IdentityProvider) map[string]*configpb.IdentityProvider {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]*configpb.IdentityProvider, len(src))
	for name, p := range src {
		out[name] = &configpb.IdentityProvider{
			Issuer:        p.Issuer,
			JwksUrl:       p.JWKSURL,
			SupportedAlgs: slices.Clone(p.SupportedAlgs),
			Audiences:     slices.Clone(p.Audiences),
		}
	}
	return out
}

// setIdentityProviders copies the proto map into the Options slot.
//
// Follows the same pattern as setMap elsewhere in this package: an empty
// incoming map is NOT applied — empty in proto can mean "not set in this
// fragment" (multiple Settings fragments are merged sequentially via
// ApplySettings), and clearing would clobber an earlier fragment. A non-empty
// map replaces the destination wholesale.
func setIdentityProviders(dst *map[string]IdentityProvider, src map[string]*configpb.IdentityProvider) {
	if len(src) == 0 {
		return
	}
	out := make(map[string]IdentityProvider, len(src))
	for name, p := range src {
		out[name] = IdentityProvider{
			Issuer:        p.GetIssuer(),
			JWKSURL:       p.GetJwksUrl(),
			SupportedAlgs: slices.Clone(p.GetSupportedAlgs()),
			Audiences:     slices.Clone(p.GetAudiences()),
		}
	}
	*dst = out
}

// ErrNoMatchingIdentityProvider is returned by IdentityProviderResolver.Verify
// and ResolveName when the token's `iss` claim does not match any configured
// identity provider.
var ErrNoMatchingIdentityProvider = errors.New("config/identity_provider: no identity provider matches the token's iss claim")

// IdentityProviderVerifyResult is the successful outcome of
// IdentityProviderResolver.Verify.
type IdentityProviderVerifyResult struct {
	// ProviderName is the name (Options.IdentityProviders map key) of the
	// provider that verified the token. It is the workload's identity-provider
	// identity, used for the session's idp_id, user-id prefix, and cache keys.
	ProviderName string
	// Claims is the verified JWT payload.
	Claims map[string]any
}

// resolvedIdentityProvider is the per-issuer verification context: the provider
// name (for identity), the provider's audiences (for audience binding), and the
// verifier.
type resolvedIdentityProvider struct {
	Name      string
	Audiences []string
	Provider  *extjwt.Provider
}

// IdentityProviderResolver owns one *extjwt.Provider per configured identity
// provider and verifies incoming bearer tokens against whichever provider's
// issuer matches the token's `iss` claim.
//
// Construct once per Options snapshot; the provider instances are immutable
// after creation.
type IdentityProviderResolver struct {
	byIssuer map[string]resolvedIdentityProvider // key: issuer
}

// NewIdentityProviderResolver builds a resolver from the given providers, keyed
// by name. httpClient (if non-nil) is used for all JWKS/discovery fetches — e.g.
// a CA-aware client for issuers behind a private CA. Providers with a
// kubernetes:// issuer are an exception: their real issuer is discovered from
// the in-cluster API server (a bounded network call at build time) and their
// fetches use a dedicated ServiceAccount-authenticated client instead. Returns
// an error if any provider is invalid or two share the same (resolved) issuer.
func NewIdentityProviderResolver(providers map[string]IdentityProvider, httpClient *http.Client, opts ...identityProviderResolverOption) (*IdentityProviderResolver, error) {
	var rc identityProviderResolverConfig
	for _, opt := range opts {
		opt(&rc)
	}
	r := &IdentityProviderResolver{
		byIssuer: make(map[string]resolvedIdentityProvider, len(providers)),
	}
	// Sorted-name order keeps errors (e.g. duplicate-issuer) deterministic.
	for _, name := range slices.Sorted(maps.Keys(providers)) {
		ip := providers[name]
		if err := validateProviderName(name); err != nil {
			return nil, err
		}
		if err := ip.Validate(); err != nil {
			return nil, fmt.Errorf("identity_providers[%s]: %w", name, err)
		}
		issuer, jwksURL, client := ip.Issuer, ip.JWKSURL, httpClient
		if isK8s, apiHost := parseKubernetesIssuer(ip.Issuer); isK8s {
			// kubernetes:// issuer: discover the real issuer from the in-cluster
			// API server, eagerly. This is a network call at config-load time,
			// acceptable because the in-cluster API is a hard dependency of the
			// pod; it is bounded by kubernetesDiscoveryTimeout and fails with a
			// clear error instead of silently rejecting every token later.
			params := defaultKubernetesInClusterParams(apiHost)
			if rc.kubernetesParams != nil {
				params = *rc.kubernetesParams
			}
			kc, err := newKubernetesHTTPClient(params)
			if err != nil {
				return nil, fmt.Errorf("identity_providers[%s]: %w", name, err)
			}
			issuer, jwksURL, err = resolveKubernetesIssuer(context.Background(), kc, params)
			if err != nil {
				return nil, fmt.Errorf("identity_providers[%s]: %w", name, err)
			}
			client = kc
		}
		// Dedup by the RESOLVED issuer: it is the byIssuer dispatch key, and a
		// kubernetes:// provider may collide with an explicitly-configured one.
		if existing, dup := r.byIssuer[issuer]; dup {
			return nil, fmt.Errorf("identity_providers: issuer %q used by both %q and %q",
				issuer, existing.Name, name)
		}
		p, err := extjwt.New(extjwt.Config{
			Issuer:        issuer,
			JWKSURL:       jwksURL,
			SupportedAlgs: ip.EffectiveSupportedAlgs(),
			HTTPClient:    client,
		})
		if err != nil {
			return nil, fmt.Errorf("identity_providers[%s]: %w", name, err)
		}
		r.byIssuer[issuer] = resolvedIdentityProvider{
			Name:      name,
			Audiences: slices.Clone(ip.Audiences),
			Provider:  p,
		}
	}
	return r, nil
}

// ResolveName returns the name of the provider whose issuer matches the token's
// UNVERIFIED `iss` claim, without performing any signature/audience checks. It
// is used to enforce a route's provider allowlist before the (expensive)
// verification runs. Returns ErrNoMatchingIdentityProvider if no provider
// matches.
func (r *IdentityProviderResolver) ResolveName(rawJWT string) (string, error) {
	iss, err := unverifiedIssuer(rawJWT)
	if err != nil {
		return "", fmt.Errorf("config/identity_provider: parse iss: %w", err)
	}
	rp, ok := r.byIssuer[iss]
	if !ok {
		return "", ErrNoMatchingIdentityProvider
	}
	return rp.Name, nil
}

// Verify verifies the raw JWT against the provider whose issuer matches the
// token's `iss` claim, enforcing that provider's audiences (fail-closed).
//
// Dispatch:
//  1. Parse the token's `iss` claim (no signature check yet).
//  2. Look up the provider with that issuer.
//  3. Verify signature/exp/nbf via that provider's verifier, with `aud`
//     checked against the provider's configured audiences.
//
// Unverified-`iss` dispatch is safe: the matched verifier re-checks `iss`,
// signature, and exp/nbf. Returns ErrNoMatchingIdentityProvider if no provider
// matches.
func (r *IdentityProviderResolver) Verify(ctx context.Context, rawJWT string) (*IdentityProviderVerifyResult, error) {
	iss, err := unverifiedIssuer(rawJWT)
	if err != nil {
		return nil, fmt.Errorf("config/identity_provider: parse iss: %w", err)
	}
	rp, ok := r.byIssuer[iss]
	if !ok {
		return nil, ErrNoMatchingIdentityProvider
	}
	claims, err := rp.Provider.Verify(ctx, rawJWT, rp.Audiences)
	if err != nil {
		return nil, err
	}
	return &IdentityProviderVerifyResult{
		ProviderName: rp.Name,
		Claims:       claims,
	}, nil
}

// IdentityProviderResolver returns a cached resolver built from cfg.Options.
// Built once per Config instance. Returns nil (no error) when no identity
// providers are configured.
func (cfg *Config) IdentityProviderResolver() (*IdentityProviderResolver, error) {
	if cfg == nil || cfg.Options == nil || len(cfg.Options.IdentityProviders) == 0 {
		return nil, nil
	}
	cfg.identityProviderResolverOnce.Do(func() {
		client, err := cfg.identityProviderHTTPClient()
		if err != nil {
			cfg.identityProviderResolverErr = err
			return
		}
		cfg.identityProviderResolver, cfg.identityProviderResolverErr = NewIdentityProviderResolver(
			cfg.Options.IdentityProviders, client)
	})
	return cfg.identityProviderResolver, cfg.identityProviderResolverErr
}

// identityProviderHTTPClient builds the HTTP client used for JWKS/discovery
// fetches. When a global certificate_authority / certificate_authority_file is
// configured (e.g. Kubernetes' cluster CA), it returns a CA-aware client;
// when neither is set it returns nil so go-oidc uses its default client with
// system roots.
//
// A CA that is explicitly configured but fails to load is a hard error, not a
// silent fallback: falling back to system roots would make the intended
// private-CA issuer's JWKS/discovery fetch fail with "unknown authority" and
// silently reject every token, with only a single startup log line. The
// misconfiguration must surface to the caller instead.
func (cfg *Config) identityProviderHTTPClient() (*http.Client, error) {
	o := cfg.Options
	if o.CA == "" && o.CAFile == "" {
		return nil, nil
	}
	rootCAs, err := cryptutil.GetCertPool(o.CA, o.CAFile)
	if err != nil {
		return nil, fmt.Errorf("config: identity_providers: error building CA cert pool: %w", err)
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
	return &http.Client{Transport: transport}, nil
}

// unverifiedIssuer extracts the `iss` claim from the JWT payload WITHOUT
// verifying the signature. Used only to dispatch to the correct verifier; the
// matched verifier then performs full verification including signature and
// `iss` re-check.
func unverifiedIssuer(rawJWT string) (string, error) {
	parts := strings.SplitN(rawJWT, ".", 3)
	if len(parts) != 3 {
		return "", fmt.Errorf("malformed JWT (expected 3 parts)")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return "", fmt.Errorf("unmarshal payload: %w", err)
	}
	if c.Iss == "" {
		return "", fmt.Errorf("missing iss claim")
	}
	return c.Iss, nil
}
