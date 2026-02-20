package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
)

// upstreamOAuthSetupConfig holds configuration for the upstream OAuth discovery + client_id setup workflow.
type upstreamOAuthSetupConfig struct {
	storage                  handlerStorage         // for caching DCR registrations (optional — skips cache if nil)
	wwwAuth                  *WWWAuthenticateParams // nil for proactive path
	fallbackAuthorizationURL string                 // AS issuer URL fallback when PRM fails (from config)
}

// UpstreamOAuthSetupOption configures the upstream OAuth setup workflow.
type UpstreamOAuthSetupOption func(*upstreamOAuthSetupConfig)

// WithStorage sets the storage backend for caching DCR registrations.
func WithStorage(s handlerStorage) UpstreamOAuthSetupOption {
	return func(c *upstreamOAuthSetupConfig) {
		c.storage = s
	}
}

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

// upstreamOAuthSetupResult holds the results of the upstream OAuth setup workflow.
type upstreamOAuthSetupResult struct {
	Discovery    *discoveryResult
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

// runUpstreamOAuthSetup performs the full upstream OAuth discovery + client_id determination workflow.
// It runs PRM discovery, determines client_id via CIMD or DCR, and selects scopes.
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

	discovery, err := runDiscovery(ctx, httpClient, cfg.wwwAuth, resourceURL, cfg.fallbackAuthorizationURL)
	if err != nil {
		return nil, fmt.Errorf("running discovery: %w", err)
	}

	redirectURI := buildCallbackURL(downstreamHost)

	// Determine client_id via DCR or CIMD.
	// Prefer DCR when available: as a proxy, our CIMD URL may not be reachable from the
	// upstream AS (e.g., local dev domains), whereas DCR registers directly with the AS.
	var clientID, clientSecret string
	if discovery.RegistrationEndpoint != "" {
		clientID, clientSecret, err = getOrRegisterClient(ctx, cfg.storage, httpClient,
			discovery.Issuer, discovery.RegistrationEndpoint, downstreamHost, redirectURI)
		if err != nil {
			return nil, fmt.Errorf("dynamic client registration: %w", err)
		}
	} else if discovery.ClientIDMetadataDocumentSupported {
		clientID = buildClientIDURL(downstreamHost)
	} else {
		return nil, fmt.Errorf("upstream authorization server %s does not support "+
			"client_id_metadata_document or dynamic client registration", discovery.Issuer)
	}

	scopes := selectScopes(cfg.wwwAuth, discovery.ScopesSupported)

	return &upstreamOAuthSetupResult{
		Discovery:    discovery,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		Scopes:       scopes,
	}, nil
}

// discoveryResult holds the output of upstream metadata discovery.
type discoveryResult struct {
	AuthorizationEndpoint             string
	TokenEndpoint                     string
	Issuer                            string
	ScopesSupported                   []string
	RegistrationEndpoint              string
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
) (*discoveryResult, error) {
	// Step 1: Fetch Protected Resource Metadata (RFC 9728)
	var prm *ProtectedResourceMetadata
	var prmErr error

	if wwwAuth != nil && wwwAuth.ResourceMetadata != "" {
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
		return runDiscoveryFromPRM(ctx, httpClient, prm, upstreamServerURL)
	}

	// Step 3: PRM not available — fall back to direct AS metadata discovery.
	// Per MCP spec: "Abort or use pre-configured values."
	// Use explicit override if configured, otherwise try the upstream server's origin.
	fallbackASURL := overrideASURL
	if fallbackASURL == "" {
		fallbackASURL, _ = originOf(upstreamServerURL)
	}
	if fallbackASURL != "" {
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
) (*discoveryResult, error) {
	// RFC 9728 §3.3: the resource value in the PRM MUST match the resource identifier
	// from which the well-known URL was derived. Prevents impersonation attacks (§7.3).
	if normalizeResourceURL(prm.Resource) != normalizeResourceURL(upstreamServerURL) {
		return nil, fmt.Errorf("PRM resource %q does not match upstream server %q", prm.Resource, upstreamServerURL)
	}

	if len(prm.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("no authorization servers in PRM")
	}

	asIssuerURL := prm.AuthorizationServers[0]
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
		Issuer:                            asm.Issuer,
		ScopesSupported:                   prm.ScopesSupported,
		RegistrationEndpoint:              asm.RegistrationEndpoint,
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
		Issuer:                            asm.Issuer,
		RegistrationEndpoint:              asm.RegistrationEndpoint,
		ClientIDMetadataDocumentSupported: asm.ClientIDMetadataDocumentSupported,
		Resource:                          resource,
	}, nil
}

// registerWithUpstreamAS performs RFC 7591 dynamic client registration with an upstream AS.
// It registers a new OAuth client and returns the assigned client_id and optional client_secret.
func registerWithUpstreamAS(ctx context.Context, httpClient *http.Client, registrationEndpoint, redirectURI, clientName string) (clientID, clientSecret string, err error) {
	reqBody := map[string]any{
		"client_name":                clientName,
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", fmt.Errorf("marshaling registration request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, strings.NewReader(string(bodyBytes)))
	if err != nil {
		return "", "", fmt.Errorf("creating registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("sending registration request: %w", err)
	}
	defer resp.Body.Close()

	const maxResponseBytes = 1 << 20 // 1 MB
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", "", fmt.Errorf("reading registration response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("registration endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("parsing registration response: %w", err)
	}

	if result.ClientID == "" {
		return "", "", fmt.Errorf("registration response missing client_id")
	}

	return result.ClientID, result.ClientSecret, nil
}

// getOrRegisterClient returns a cached DCR registration or registers a new client.
// DCR is per-instance (not per-user): one registration is shared across all users
// for a given AS issuer + downstream host combination.
func getOrRegisterClient(
	ctx context.Context,
	storage handlerStorage,
	httpClient *http.Client,
	issuer, registrationEndpoint, downstreamHost, redirectURI string,
) (clientID, clientSecret string, err error) {
	if storage != nil {
		cached, getErr := storage.GetUpstreamOAuthClient(ctx, issuer, stripPort(downstreamHost))
		if getErr != nil {
			log.Ctx(ctx).Warn().Err(getErr).
				Str("issuer", issuer).
				Str("downstream_host", downstreamHost).
				Msg("failed to read cached DCR registration, will re-register")
		} else if cached != nil && cached.ClientId != "" {
			log.Ctx(ctx).Debug().
				Str("issuer", issuer).
				Str("downstream_host", downstreamHost).
				Str("client_id", cached.ClientId).
				Msg("using cached DCR client registration")
			return cached.ClientId, cached.ClientSecret, nil
		}
	}

	// Register new client
	clientID, clientSecret, err = registerWithUpstreamAS(ctx, httpClient,
		registrationEndpoint, redirectURI, "Pomerium MCP Proxy")
	if err != nil {
		return "", "", err
	}

	// Cache the registration
	if storage != nil {
		now := time.Now()
		if putErr := storage.PutUpstreamOAuthClient(ctx, &oauth21proto.UpstreamOAuthClient{
			Issuer:               issuer,
			DownstreamHost:       stripPort(downstreamHost),
			ClientId:             clientID,
			ClientSecret:         clientSecret,
			RedirectUri:          redirectURI,
			RegistrationEndpoint: registrationEndpoint,
			CreatedAt:            timestamppb.New(now),
		}); putErr != nil {
			// Non-fatal: registration succeeded, just couldn't cache it
			log.Ctx(ctx).Warn().Err(putErr).
				Str("issuer", issuer).
				Str("downstream_host", downstreamHost).
				Msg("failed to cache DCR client registration")
		}
	}

	return clientID, clientSecret, nil
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
