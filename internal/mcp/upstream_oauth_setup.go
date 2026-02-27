package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/pomerium/pomerium/internal/log"
)

// upstreamOAuthSetupConfig holds configuration for the upstream OAuth discovery + client_id setup workflow.
type upstreamOAuthSetupConfig struct {
	wwwAuth                  *WWWAuthenticateParams // nil for proactive path
	fallbackAuthorizationURL string                 // AS issuer URL fallback when PRM fails (from config)
	asMetadataDomainMatcher  *DomainMatcher         // allowlist for upstream AS/PRM metadata URL domains
	allowDCRFallback         bool
}

// UpstreamOAuthSetupOption configures the upstream OAuth setup workflow.
type UpstreamOAuthSetupOption func(*upstreamOAuthSetupConfig)

// WithWWWAuthenticate sets the parsed WWW-Authenticate parameters from an upstream 401 response.
func WithWWWAuthenticate(wwwAuth *WWWAuthenticateParams) UpstreamOAuthSetupOption {
	return func(c *upstreamOAuthSetupConfig) {
		c.wwwAuth = wwwAuth
	}
}

// WithFallbackAuthorizationURL sets the AS issuer URL to use when PRM discovery fails.
func WithFallbackAuthorizationURL(u string) UpstreamOAuthSetupOption {
	return func(c *upstreamOAuthSetupConfig) {
		c.fallbackAuthorizationURL = u
	}
}

// WithASMetadataDomainMatcher sets the domain matcher for validating upstream
// AS/PRM metadata URL domains before fetching. If nil, all metadata URL
// validations will be rejected (resource_metadata hints from WWW-Authenticate,
// authorization_servers entries from PRM, and fallback AS URLs).
func WithASMetadataDomainMatcher(m *DomainMatcher) UpstreamOAuthSetupOption {
	return func(c *upstreamOAuthSetupConfig) {
		c.asMetadataDomainMatcher = m
	}
}

// WithAllowDCRFallback enables fallback to Dynamic Client Registration (RFC 7591)
// when the upstream AS does not support client_id metadata documents.
func WithAllowDCRFallback(v bool) UpstreamOAuthSetupOption {
	return func(c *upstreamOAuthSetupConfig) {
		c.allowDCRFallback = v
	}
}

// upstreamOAuthSetupResult holds the results of the upstream OAuth setup workflow.
type upstreamOAuthSetupResult struct {
	Discovery    *discoveryResult
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

// runUpstreamOAuthSetup performs the full upstream OAuth discovery + client_id determination workflow.
// It runs PRM discovery, determines client_id via CIMD, and selects scopes.
// Returns an error if discovery fails and no fallback AS metadata is available.
func runUpstreamOAuthSetup(
	ctx context.Context,
	httpClient *http.Client,
	resourceURL string,
	downstreamHost string,
	opts ...UpstreamOAuthSetupOption,
) (*upstreamOAuthSetupResult, error) {
	var cfg upstreamOAuthSetupConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	discovery, err := runDiscovery(ctx, httpClient, cfg.wwwAuth, resourceURL, cfg.fallbackAuthorizationURL, cfg.asMetadataDomainMatcher)
	if err != nil {
		return nil, fmt.Errorf("running discovery: %w", err)
	}

	redirectURI := buildCallbackURL(downstreamHost)

	if !discovery.ClientIDMetadataDocumentSupported {
		if cfg.allowDCRFallback {
			if discovery.RegistrationEndpoint != "" {
				log.Ctx(ctx).Info().
					Str("issuer", discovery.Issuer).
					Str("registration_endpoint", discovery.RegistrationEndpoint).
					Msg("ext_proc: upstream AS does not support client_id_metadata_document, falling back to DCR")
			} else {
				return nil, fmt.Errorf("upstream authorization server %s does not support "+
					"client_id_metadata_document; DCR fallback enabled but AS does not advertise "+
					"a registration_endpoint", discovery.Issuer)
			}
		} else {
			return nil, fmt.Errorf("upstream authorization server %s does not support "+
				"client_id_metadata_document", discovery.Issuer)
		}
	}

	clientID := ""
	if discovery.ClientIDMetadataDocumentSupported {
		clientID = buildClientIDURL(downstreamHost)
	}

	scopes := selectScopes(cfg.wwwAuth, discovery.ScopesSupported)

	return &upstreamOAuthSetupResult{
		Discovery:   discovery,
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scopes:      scopes,
	}, nil
}

// discoveryResult holds the output of upstream metadata discovery.
type discoveryResult struct {
	AuthorizationEndpoint             string
	TokenEndpoint                     string
	RegistrationEndpoint              string
	Issuer                            string
	ScopesSupported                   []string
	ClientIDMetadataDocumentSupported bool
	// Resource is the canonical resource identifier for the upstream MCP server.
	// When PRM is available, this is prm.Resource (authoritative).
	// When PRM is unavailable (fallback), this is the origin of the upstream URL.
	Resource string
}

// runDiscovery fetches Protected Resource Metadata (RFC 9728) and Authorization Server Metadata.
// Per the MCP spec (Protocol Revision 2025-11-25), PRM is REQUIRED:
// "MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728)."
// Discovery order: WWW-Authenticate resource_metadata > well-known PRM sub-path > well-known PRM root.
// If PRM is unavailable, falls back to direct AS metadata discovery:
//  1. Use overrideASURL if configured (for when AS is on a different domain than the resource)
//  2. Otherwise try AS metadata at the upstream server's origin
func runDiscovery(
	ctx context.Context,
	httpClient *http.Client,
	wwwAuth *WWWAuthenticateParams,
	upstreamServerURL string,
	overrideASURL string,
	asMetadataDomainMatcher *DomainMatcher,
) (*discoveryResult, error) {
	// Step 1: Fetch Protected Resource Metadata (RFC 9728)
	var prm *ProtectedResourceMetadata
	var prmErr error

	if wwwAuth != nil && wwwAuth.ResourceMetadata != "" {
		// The resource_metadata URL comes from an untrusted upstream 401 response.
		// Validate its domain against the allowlist before making any HTTP request.
		if err := validateMetadataURL(wwwAuth.ResourceMetadata, asMetadataDomainMatcher); err != nil {
			return nil, fmt.Errorf("resource_metadata URL from WWW-Authenticate: %w", err)
		}
		log.Ctx(ctx).Debug().
			Str("resource_metadata_url", wwwAuth.ResourceMetadata).
			Msg("ext_proc: fetching PRM from WWW-Authenticate resource_metadata hint")
		prm, prmErr = FetchProtectedResourceMetadata(ctx, httpClient, wwwAuth.ResourceMetadata)
	} else {
		// Try well-known URLs
		urls, buildErr := BuildProtectedResourceMetadataURLs(upstreamServerURL)
		if buildErr != nil {
			return nil, fmt.Errorf("building PRM URLs: %w", buildErr)
		}
		log.Ctx(ctx).Debug().
			Strs("prm_urls", urls).
			Msg("ext_proc: attempting PRM discovery at well-known URLs")
		for _, u := range urls {
			prm, prmErr = FetchProtectedResourceMetadata(ctx, httpClient, u)
			if prmErr == nil {
				log.Ctx(ctx).Debug().
					Str("prm_url", u).
					Msg("ext_proc: PRM discovery succeeded")
				break
			}
			log.Ctx(ctx).Debug().
				Err(prmErr).
				Str("prm_url", u).
				Msg("ext_proc: PRM fetch failed, trying next")
		}
	}

	// Step 2: If PRM succeeded, use PRM → AS metadata flow
	if prmErr == nil && prm != nil {
		return runDiscoveryFromPRM(ctx, httpClient, prm, upstreamServerURL, asMetadataDomainMatcher)
	}

	// Step 3: PRM not available — fall back to direct AS metadata discovery.
	// Per MCP spec: "Abort or use pre-configured values."
	// Use explicit override if configured, otherwise try the upstream server's origin.
	fallbackASURL := overrideASURL
	if fallbackASURL == "" {
		fallbackASURL, _ = originOf(upstreamServerURL)
	}
	if fallbackASURL != "" {
		// Validate the fallback AS URL: enforce HTTPS and check the domain against
		// the allowlist. While these URLs are typically operator-controlled (from
		// config or route definitions), we apply the same validation as the
		// attacker-influenced paths for consistent security guarantees.
		if err := validateMetadataURL(fallbackASURL, asMetadataDomainMatcher); err != nil {
			return nil, fmt.Errorf("fallback AS URL: %w", err)
		}
		log.Ctx(ctx).Info().
			Str("upstream_url", upstreamServerURL).
			Str("fallback_as_url", fallbackASURL).
			Bool("explicit_override", overrideASURL != "").
			AnErr("prm_error", prmErr).
			Msg("ext_proc: PRM discovery failed, falling back to direct AS metadata discovery")
		return runDiscoveryFromFallbackAS(ctx, httpClient, fallbackASURL, upstreamServerURL)
	}

	if prmErr != nil {
		return nil, fmt.Errorf("fetching protected resource metadata: %w", prmErr)
	}
	return nil, fmt.Errorf("no protected resource metadata found")
}

// originOf extracts the scheme+host from a URL (e.g. "https://example.com/path" → "https://example.com").
// Returns an error if the URL cannot be parsed or is missing scheme/host.
func originOf(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("empty URL")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing URL %q: %w", rawURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("URL %q missing scheme or host", rawURL)
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String(), nil
}

// runDiscoveryFromPRM completes discovery using a successfully fetched PRM document.
func runDiscoveryFromPRM(
	ctx context.Context,
	httpClient *http.Client,
	prm *ProtectedResourceMetadata,
	upstreamServerURL string,
	asMetadataDomainMatcher *DomainMatcher,
) (*discoveryResult, error) {
	// Validate the PRM resource against the upstream server URL using path-prefix matching.
	// This is a port of the MCP TypeScript SDK's checkResourceAllowed():
	// same origin (scheme+host+port) + PRM resource path must be a prefix of the upstream path.
	allowed, err := checkResourceAllowed(upstreamServerURL, prm.Resource)
	if err != nil {
		return nil, fmt.Errorf("PRM resource validation: %w", err)
	}
	if !allowed {
		log.Ctx(ctx).Debug().
			Str("prm_resource", prm.Resource).
			Str("upstream_server", upstreamServerURL).
			Msg("ext_proc: PRM resource validation failed: not a path-prefix match")
		return nil, fmt.Errorf("PRM resource %q does not match upstream server %q", prm.Resource, upstreamServerURL)
	}
	// Log when the match succeeds via path-prefix rather than exact match
	// (normalizeResourceURL comparison is for logging only — checkResourceAllowed
	// already validated the prefix relationship).
	if normalizeResourceURL(prm.Resource) != normalizeResourceURL(upstreamServerURL) {
		log.Ctx(ctx).Info().
			Str("prm_resource", prm.Resource).
			Str("upstream_server", upstreamServerURL).
			Msg("ext_proc: PRM resource matched upstream by path-prefix")
	}

	if len(prm.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("no authorization servers in PRM")
	}

	asIssuerURL := prm.AuthorizationServers[0]

	// The authorization_servers URL is extracted from the PRM document's content.
	// Even if the PRM was fetched from a trusted well-known URL, its content
	// could direct us to an arbitrary domain. Validate before fetching.
	if err := validateMetadataURL(asIssuerURL, asMetadataDomainMatcher); err != nil {
		return nil, fmt.Errorf("authorization_servers URL from PRM: %w", err)
	}

	log.Ctx(ctx).Debug().
		Str("prm_resource", prm.Resource).
		Str("as_issuer", asIssuerURL).
		Strs("scopes_supported", prm.ScopesSupported).
		Msg("ext_proc: PRM validated, fetching AS metadata")

	asm, err := FetchAuthorizationServerMetadata(ctx, httpClient, asIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("fetching AS metadata: %w", err)
	}

	log.Ctx(ctx).Debug().
		Str("issuer", asm.Issuer).
		Str("authorization_endpoint", asm.AuthorizationEndpoint).
		Str("token_endpoint", asm.TokenEndpoint).
		Bool("has_registration_endpoint", asm.RegistrationEndpoint != "").
		Bool("cimd_supported", asm.ClientIDMetadataDocumentSupported).
		Msg("ext_proc: AS metadata discovery succeeded via PRM")

	return &discoveryResult{
		AuthorizationEndpoint:             asm.AuthorizationEndpoint,
		TokenEndpoint:                     asm.TokenEndpoint,
		RegistrationEndpoint:              asm.RegistrationEndpoint,
		Issuer:                            asm.Issuer,
		ScopesSupported:                   prm.ScopesSupported,
		ClientIDMetadataDocumentSupported: asm.ClientIDMetadataDocumentSupported,
		Resource:                          prm.Resource,
	}, nil
}

// runDiscoveryFromFallbackAS performs discovery using an AS issuer URL directly,
// bypassing PRM. Used when the upstream MCP server doesn't implement RFC 9728 PRM.
// The upstreamServerURL is used to derive the resource identifier (origin only,
// since without PRM we don't know the canonical resource URI).
func runDiscoveryFromFallbackAS(
	ctx context.Context,
	httpClient *http.Client,
	asIssuerURL string,
	upstreamServerURL string,
) (*discoveryResult, error) {
	asm, err := FetchAuthorizationServerMetadata(ctx, httpClient, asIssuerURL)
	if err != nil {
		return nil, fmt.Errorf("fetching fallback AS metadata from %s: %w", asIssuerURL, err)
	}

	// Without PRM, use the origin of the upstream URL as the resource identifier.
	// This is a best-effort guess: PRM would provide the authoritative value via
	// its "resource" field, but without PRM we use the origin as the most common
	// convention for audience values in OAuth.
	resource, err := originOf(upstreamServerURL)
	if err != nil {
		return nil, fmt.Errorf("deriving resource from upstream URL %q: %w", upstreamServerURL, err)
	}

	log.Ctx(ctx).Info().
		Str("issuer", asm.Issuer).
		Str("authorization_endpoint", asm.AuthorizationEndpoint).
		Str("token_endpoint", asm.TokenEndpoint).
		Str("resource", resource).
		Bool("has_registration_endpoint", asm.RegistrationEndpoint != "").
		Bool("cimd_supported", asm.ClientIDMetadataDocumentSupported).
		Msg("ext_proc: AS metadata discovery succeeded via fallback (no PRM)")

	return &discoveryResult{
		AuthorizationEndpoint:             asm.AuthorizationEndpoint,
		TokenEndpoint:                     asm.TokenEndpoint,
		RegistrationEndpoint:              asm.RegistrationEndpoint,
		Issuer:                            asm.Issuer,
		ClientIDMetadataDocumentSupported: asm.ClientIDMetadataDocumentSupported,
		Resource:                          resource,
	}, nil
}

// selectScopes implements the MCP scope selection strategy:
// 1. Use scope from WWW-Authenticate header if provided
// 2. Fall back to scopes_supported from Protected Resource Metadata
func selectScopes(wwwAuth *WWWAuthenticateParams, prmScopes []string) []string {
	if wwwAuth != nil && len(wwwAuth.Scope) > 0 {
		return wwwAuth.Scope
	}
	if len(prmScopes) > 0 {
		return prmScopes
	}
	return nil
}

type authorizationURLParams struct {
	ClientID            string
	RedirectURI         string
	Scopes              []string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

func buildAuthorizationURL(endpoint string, params *authorizationURLParams) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		u = &url.URL{Path: endpoint}
	}
	q := u.Query()
	q.Set("client_id", params.ClientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", params.RedirectURI)
	if len(params.Scopes) > 0 {
		q.Set("scope", strings.Join(params.Scopes, " "))
	}
	q.Set("state", params.State)
	q.Set("code_challenge", params.CodeChallenge)
	q.Set("code_challenge_method", params.CodeChallengeMethod)
	if params.Resource != "" {
		q.Set("resource", params.Resource)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func buildCallbackURL(host string) string {
	return (&url.URL{
		Scheme: "https",
		Host:   host,
		Path:   path.Join(DefaultPrefix, clientOAuthCallbackEndpoint),
	}).String()
}

func buildClientIDURL(host string) string {
	return (&url.URL{
		Scheme: "https",
		Host:   host,
		Path:   path.Join(DefaultPrefix, clientMetadataEndpoint),
	}).String()
}

// generatePKCE generates PKCE code_verifier and S256 code_challenge.
func generatePKCE() (verifier, challenge string, err error) {
	verifierBytes := make([]byte, 32)
	if _, err := rand.Read(verifierBytes); err != nil {
		return "", "", fmt.Errorf("generating random bytes: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(verifierBytes)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(hash[:])
	return verifier, challenge, nil
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func stripPort(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}
	return host
}

// stripQueryFromURL returns the URL with query string and fragment removed.
// Used to derive the resource URL from the full request URL.
func stripQueryFromURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// normalizeResourceURL normalizes a resource URL for comparison by stripping trailing slashes.
// RFC 9728 §3.3 requires exact match, but trailing slash differences are common in practice.
func normalizeResourceURL(u string) string {
	return strings.TrimRight(u, "/")
}

// checkResourceAllowed checks whether a PRM resource is valid for the given
// upstream server URL. Based on the MCP TypeScript SDK's checkResourceAllowed().
// Requires same origin (scheme+host+port, case-insensitive per RFC 3986) and
// that the PRM resource path is a prefix of the upstream server URL path.
// Paths are cleaned (resolving ".." and ".") before comparison.
// Trailing-slash normalization prevents /api matching /api123, and an early
// length guard ensures that a resource with a longer path (e.g. /folder/)
// never matches a shorter upstream path (e.g. /folder).
func checkResourceAllowed(upstreamServerURL, prmResource string) (bool, error) {
	upstream, err := url.Parse(upstreamServerURL)
	if err != nil {
		return false, fmt.Errorf("parsing upstream URL %q: %w", upstreamServerURL, err)
	}
	if upstream.Scheme == "" || upstream.Host == "" {
		return false, fmt.Errorf("upstream URL %q missing scheme or host", upstreamServerURL)
	}
	resource, err := url.Parse(prmResource)
	if err != nil {
		return false, fmt.Errorf("parsing PRM resource %q: %w", prmResource, err)
	}
	if resource.Scheme == "" || resource.Host == "" {
		return false, fmt.Errorf("PRM resource %q missing scheme or host", prmResource)
	}

	// Same origin check (scheme + host, where host includes port).
	// Use case-insensitive comparison per RFC 3986 §3.1 (scheme) and §3.2.2 (host).
	if !strings.EqualFold(upstream.Scheme, resource.Scheme) || !strings.EqualFold(upstream.Host, resource.Host) {
		return false, nil
	}

	// Normalize paths: resolve ".." and "." segments, then normalize empty path to "/".
	upstreamPath := path.Clean(upstream.Path)
	if upstreamPath == "." || upstreamPath == "" {
		upstreamPath = "/"
	}
	resourcePath := path.Clean(resource.Path)
	if resourcePath == "." || resourcePath == "" {
		resourcePath = "/"
	}

	// Early length guard: if the cleaned resource path is longer than the cleaned
	// upstream path, it cannot be a prefix.
	if len(resourcePath) > len(upstreamPath) {
		return false, nil
	}

	// Trailing-slash normalization for prefix check (prevents /api matching /api123)
	if !strings.HasSuffix(upstreamPath, "/") {
		upstreamPath += "/"
	}
	if !strings.HasSuffix(resourcePath, "/") {
		resourcePath += "/"
	}

	return strings.HasPrefix(upstreamPath, resourcePath), nil
}

// validateMetadataURL validates a metadata URL's scheme and domain.
// Enforces HTTPS and checks the domain against the allowlist.
// This is the SSRF prevention gate for upstream AS/PRM metadata URLs that originate
// from untrusted sources (WWW-Authenticate headers, PRM documents).
func validateMetadataURL(rawURL string, domainMatcher *DomainMatcher) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("parsing URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("%w: metadata URL must use https, got %q", ErrSSRFBlocked, u.Scheme)
	}
	if domainMatcher == nil {
		return fmt.Errorf("%w: no allowed AS metadata domains configured", ErrDomainNotAllowed)
	}
	if err := domainMatcher.ValidateURLDomain(u); err != nil {
		return err
	}
	return nil
}
