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

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"golang.org/x/sync/singleflight"
	googlegrpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/mcp/extproc"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

const (
	// pendingAuthExpiry is the maximum lifetime for pending upstream authorization state.
	pendingAuthExpiry = 5 * time.Minute
)

// UpstreamAuthHandler implements extproc.UpstreamRequestHandler for MCP upstream OAuth flows.
// It handles token injection on the request path and 401/403 interception on the response path.
// For routes with static upstream_oauth2 config, it uses the config-based token source.
// For routes with auto-discovery (no upstream_oauth2 config), it uses the MCP discovery flow.
type UpstreamAuthHandler struct {
	storage      handlerStorage
	hosts        *HostInfo
	httpClient   *http.Client
	singleFlight singleflight.Group
}

// NewUpstreamAuthHandler creates a new UpstreamAuthHandler.
func NewUpstreamAuthHandler(
	storage handlerStorage,
	hosts *HostInfo,
	httpClient *http.Client,
) *UpstreamAuthHandler {
	return &UpstreamAuthHandler{
		storage:    storage,
		hosts:      hosts,
		httpClient: httpClient,
	}
}

// NewUpstreamAuthHandlerFromConfig creates an UpstreamAuthHandler using the provided config
// and outbound gRPC connection. This is the primary factory used by the controlplane server.
func NewUpstreamAuthHandlerFromConfig(
	ctx context.Context,
	cfg *config.Config,
	outboundGrpcConn *grpc.CachedOutboundGRPClientConn,
) (*UpstreamAuthHandler, error) {
	tracerProvider := trace.NewTracerProvider(ctx, "MCP-ExtProc")

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, fmt.Errorf("shared key: %w", err)
	}

	dataBrokerConn, err := outboundGrpcConn.Get(ctx, &grpc.OutboundOptions{
		OutboundPort:   cfg.OutboundPort,
		InstallationID: cfg.Options.InstallationID,
		ServiceName:    cfg.Options.Services,
		SignedJWTKey:   sharedKey,
	}, googlegrpc.WithStatsHandler(otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(tracerProvider))))
	if err != nil {
		return nil, fmt.Errorf("databroker connection: %w", err)
	}

	storage := NewStorage(databroker.NewDataBrokerServiceClient(dataBrokerConn))
	hosts := NewHostInfo(cfg, http.DefaultClient)

	return NewUpstreamAuthHandler(storage, hosts, http.DefaultClient), nil
}

// GetUpstreamToken looks up a cached upstream token for the given route context and host.
// For routes with static upstream_oauth2 config, uses the config-based token source.
// For auto-discovery routes, looks up cached MCP tokens and refreshes if expired.
// Returns empty string if no token is available.
func (h *UpstreamAuthHandler) GetUpstreamToken(
	ctx context.Context,
	routeCtx *extproc.RouteContext,
	host string,
) (string, error) {
	hostname := stripPort(host)

	// Check for static upstream_oauth2 config first
	if _, ok := h.hosts.GetOAuth2ConfigForHost(hostname); ok {
		return h.getStaticUpstreamOAuth2Token(ctx, routeCtx, hostname)
	}

	// Fall through to auto-discovery MCP token path
	if !h.hosts.UsesAutoDiscovery(hostname) {
		return "", nil
	}

	return h.getAutoDiscoveryToken(ctx, routeCtx, hostname)
}

// getStaticUpstreamOAuth2Token retrieves a token using the static upstream_oauth2 config.
// Uses singleflight to deduplicate concurrent refresh requests for the same host.
func (h *UpstreamAuthHandler) getStaticUpstreamOAuth2Token(
	ctx context.Context,
	routeCtx *extproc.RouteContext,
	hostname string,
) (string, error) {
	userID, err := h.getUserID(ctx, routeCtx.SessionID)
	if err != nil {
		if isNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("getting user ID for static token: %w", err)
	}

	sfKey := hostname + ":" + userID
	token, err, _ := h.singleFlight.Do(sfKey, func() (any, error) {
		tokenPB, err := h.storage.GetUpstreamOAuth2Token(ctx, hostname, userID)
		if err != nil {
			return "", fmt.Errorf("getting upstream oauth2 token: %w", err)
		}

		cfg, ok := h.hosts.GetOAuth2ConfigForHost(hostname)
		if !ok {
			return "", fmt.Errorf("no OAuth2 config found for host %s", hostname)
		}

		tok, err := cfg.TokenSource(ctx, PBToOAuth2Token(tokenPB)).Token()
		if err != nil {
			return "", fmt.Errorf("getting OAuth2 token: %w", err)
		}

		if tok.RefreshToken == "" {
			tok.RefreshToken = tokenPB.GetRefreshToken()
		}

		if tok.AccessToken != tokenPB.GetAccessToken() ||
			tok.RefreshToken != tokenPB.GetRefreshToken() {
			if err := h.storage.StoreUpstreamOAuth2Token(ctx, hostname, userID, OAuth2TokenToPB(tok)); err != nil {
				return "", fmt.Errorf("storing updated upstream oauth2 token: %w", err)
			}
		}

		return tok.AccessToken, nil
	})
	if err != nil {
		return "", err
	}
	return token.(string), nil
}

// getAutoDiscoveryToken looks up a cached MCP token for the auto-discovery flow.
// If the token is expired but has a refresh token, attempts inline refresh.
func (h *UpstreamAuthHandler) getAutoDiscoveryToken(
	ctx context.Context,
	routeCtx *extproc.RouteContext,
	hostname string,
) (string, error) {
	upstreamServer, err := h.getUpstreamServerURL(hostname)
	if err != nil {
		return "", fmt.Errorf("getting upstream server URL: %w", err)
	}

	userID, err := h.getUserID(ctx, routeCtx.SessionID)
	if err != nil {
		if isNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("getting user ID for auto-discovery token: %w", err)
	}

	token, err := h.storage.GetUpstreamMCPToken(ctx, userID, routeCtx.RouteID, upstreamServer)
	if err != nil {
		if isNotFound(err) {
			return "", nil
		}
		return "", fmt.Errorf("looking up upstream token: %w", err)
	}

	// Check if access token is expired
	if token.ExpiresAt != nil && token.ExpiresAt.AsTime().Before(time.Now()) {
		// Try refresh if we have a refresh token and token endpoint.
		// Uses singleflight to deduplicate concurrent refresh requests.
		if token.RefreshToken != "" && token.TokenEndpoint != "" {
			sfKey := fmt.Sprintf("mcp:%s:%s:%s", userID, routeCtx.RouteID, upstreamServer)
			result, err, _ := h.singleFlight.Do(sfKey, func() (any, error) {
				return h.refreshToken(ctx, token)
			})
			if err != nil {
				log.Ctx(ctx).Warn().Err(err).
					Str("user_id", userID).
					Str("route_id", routeCtx.RouteID).
					Msg("ext_proc: token refresh failed, clearing cached token")
				if delErr := h.storage.DeleteUpstreamMCPToken(ctx, userID, routeCtx.RouteID, upstreamServer); delErr != nil {
					log.Ctx(ctx).Error().Err(delErr).Msg("ext_proc: failed to delete stale token after refresh failure")
				}
				return "", nil
			}
			refreshed := result.(*oauth21proto.UpstreamMCPToken)
			return refreshed.AccessToken, nil
		}
		// Expired with no refresh token - clear it
		log.Ctx(ctx).Debug().
			Str("user_id", userID).
			Str("route_id", routeCtx.RouteID).
			Msg("ext_proc: upstream token expired with no refresh token, clearing")
		if delErr := h.storage.DeleteUpstreamMCPToken(ctx, userID, routeCtx.RouteID, upstreamServer); delErr != nil {
			log.Ctx(ctx).Error().Err(delErr).Msg("ext_proc: failed to delete expired token")
		}
		return "", nil
	}

	return token.AccessToken, nil
}

// HandleUpstreamResponse processes a 401/403 response from upstream.
// For 401: runs discovery, generates PKCE, stores pending auth state, returns 401 action.
// For 403 with insufficient_scope: similar but with expanded scopes.
// Returns nil if the response should be passed through.
func (h *UpstreamAuthHandler) HandleUpstreamResponse(
	ctx context.Context,
	routeCtx *extproc.RouteContext,
	host, originalURL string,
	statusCode int,
	wwwAuthenticate string,
) (*extproc.UpstreamAuthAction, error) {
	hostname := stripPort(host)
	if !h.hosts.UsesAutoDiscovery(hostname) {
		return nil, nil
	}

	wwwAuth := ParseWWWAuthenticate(wwwAuthenticate)

	switch statusCode {
	case 401:
		return h.handle401(ctx, routeCtx, host, hostname, originalURL, wwwAuth)
	case 403:
		if wwwAuth != nil && wwwAuth.Error == "insufficient_scope" {
			return h.handle401(ctx, routeCtx, host, hostname, originalURL, wwwAuth)
		}
		return nil, nil
	default:
		return nil, nil
	}
}

// handle401 handles a 401 (or 403 insufficient_scope) from upstream by running discovery,
// storing pending auth state with an index, and returning a 401 action for the MCP client.
func (h *UpstreamAuthHandler) handle401(
	ctx context.Context,
	routeCtx *extproc.RouteContext,
	host, hostname, originalURL string,
	wwwAuth *WWWAuthenticateParams,
) (*extproc.UpstreamAuthAction, error) {
	upstreamServer, err := h.getUpstreamServerURL(hostname)
	if err != nil {
		return nil, fmt.Errorf("getting upstream server URL: %w", err)
	}

	// The resource URL is the actual URL the client was trying to access (with path).
	// This is used for PRM discovery/validation and the OAuth resource parameter.
	// The base upstreamServer URL is used for token storage keys (must match getAutoDiscoveryToken).
	resourceURL := stripQueryFromURL(originalURL)

	userID, err := h.getUserID(ctx, routeCtx.SessionID)
	if err != nil {
		return nil, fmt.Errorf("getting user ID: %w", err)
	}

	setup, err := runUpstreamOAuthSetup(ctx, &upstreamOAuthSetupParams{
		HTTPClient:     h.httpClient,
		Storage:        h.storage,
		UpstreamURL:    upstreamServer,
		ResourceURL:    resourceURL,
		DownstreamHost: host,
		WWWAuth:        wwwAuth,
	})
	if err != nil {
		return nil, err
	}

	// Generate PKCE
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return nil, fmt.Errorf("generating PKCE: %w", err)
	}

	// Generate state
	stateID, err := generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("generating state: %w", err)
	}

	// Store pending authorization.
	// UpstreamServer uses the base URL for consistent token storage keys.
	now := time.Now()
	pending := &oauth21proto.PendingUpstreamAuth{
		StateId:                   stateID,
		UserId:                    userID,
		RouteId:                   routeCtx.RouteID,
		UpstreamServer:            upstreamServer,
		PkceVerifier:              verifier,
		PkceChallenge:             challenge,
		Scopes:                    setup.Scopes,
		AuthorizationEndpoint:     setup.Discovery.AuthorizationEndpoint,
		TokenEndpoint:             setup.Discovery.TokenEndpoint,
		AuthorizationServerIssuer: setup.Discovery.Issuer,
		OriginalUrl:               originalURL,
		RedirectUri:               setup.RedirectURI,
		ClientId:                  setup.ClientID,
		ClientSecret:              setup.ClientSecret,
		DownstreamHost:            host,
		CreatedAt:                 timestamppb.New(now),
		ExpiresAt:                 timestamppb.New(now.Add(pendingAuthExpiry)),
	}

	if err := h.storage.PutPendingUpstreamAuth(ctx, pending); err != nil {
		return nil, fmt.Errorf("storing pending auth: %w", err)
	}

	// Return 401 with Pomerium's own PRM so the MCP client re-runs its auth flow.
	prmURL := (&url.URL{
		Scheme: "https",
		Host:   host,
		Path:   WellKnownProtectedResourceEndpoint,
	}).String()

	return &extproc.UpstreamAuthAction{
		WWWAuthenticate: fmt.Sprintf(`Bearer resource_metadata="%s"`, prmURL),
	}, nil
}

// upstreamOAuthSetupParams holds parameters for the upstream OAuth discovery + client_id setup workflow.
type upstreamOAuthSetupParams struct {
	HTTPClient     *http.Client
	Storage        handlerStorage         // for caching DCR registrations (optional — skips cache if nil)
	UpstreamURL    string                 // base URL for token storage keys
	ResourceURL    string                 // full URL for PRM discovery + resource param
	DownstreamHost string                 // for callback/CIMD URLs
	WWWAuth        *WWWAuthenticateParams // nil for proactive path
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
// Returns nil result (not error) if PRM is not available (upstream doesn't need OAuth).
func runUpstreamOAuthSetup(ctx context.Context, params *upstreamOAuthSetupParams) (*upstreamOAuthSetupResult, error) {
	discovery, err := runDiscovery(ctx, params.HTTPClient, params.WWWAuth, params.ResourceURL)
	if err != nil {
		return nil, fmt.Errorf("running discovery: %w", err)
	}

	redirectURI := buildCallbackURL(params.DownstreamHost)

	// Determine client_id via DCR or CIMD.
	// Prefer DCR when available: as a proxy, our CIMD URL may not be reachable from the
	// upstream AS (e.g., local dev domains), whereas DCR registers directly with the AS.
	var clientID, clientSecret string
	if discovery.RegistrationEndpoint != "" {
		clientID, clientSecret, err = getOrRegisterClient(ctx, params.Storage, params.HTTPClient,
			discovery.Issuer, discovery.RegistrationEndpoint, params.DownstreamHost, redirectURI)
		if err != nil {
			return nil, fmt.Errorf("dynamic client registration: %w", err)
		}
	} else if discovery.ClientIDMetadataDocumentSupported {
		clientID = buildClientIDURL(params.DownstreamHost)
	} else {
		return nil, fmt.Errorf("upstream authorization server %s does not support "+
			"client_id_metadata_document or dynamic client registration", discovery.Issuer)
	}

	scopes := selectScopes(params.WWWAuth, discovery.ScopesSupported)

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
}

// runDiscovery fetches Protected Resource Metadata (RFC 9728) and Authorization Server Metadata.
// Per the MCP spec (Protocol Revision 2025-11-25), PRM is REQUIRED:
// "MCP servers MUST implement OAuth 2.0 Protected Resource Metadata (RFC9728)."
// Discovery order: WWW-Authenticate resource_metadata > well-known PRM sub-path > well-known PRM root.
// If PRM is unavailable, discovery fails (per spec: "abort or use pre-configured values").
func runDiscovery(
	ctx context.Context,
	httpClient *http.Client,
	wwwAuth *WWWAuthenticateParams,
	upstreamServerURL string,
) (*discoveryResult, error) {
	// Fetch Protected Resource Metadata
	var prm *ProtectedResourceMetadata
	var err error

	if wwwAuth != nil && wwwAuth.ResourceMetadata != "" {
		prm, err = FetchProtectedResourceMetadata(ctx, httpClient, wwwAuth.ResourceMetadata)
	} else {
		// Try well-known URLs
		urls, buildErr := BuildProtectedResourceMetadataURLs(upstreamServerURL)
		if buildErr != nil {
			return nil, fmt.Errorf("building PRM URLs: %w", buildErr)
		}
		for _, u := range urls {
			prm, err = FetchProtectedResourceMetadata(ctx, httpClient, u)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("fetching protected resource metadata: %w", err)
	}
	if prm == nil {
		return nil, fmt.Errorf("no protected resource metadata found")
	}

	// RFC 9728 §3.3: the resource value in the PRM MUST match the resource identifier
	// from which the well-known URL was derived. Prevents impersonation attacks (§7.3).
	if normalizeResourceURL(prm.Resource) != normalizeResourceURL(upstreamServerURL) {
		return nil, fmt.Errorf("PRM resource %q does not match upstream server %q", prm.Resource, upstreamServerURL)
	}

	if len(prm.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("no authorization servers in PRM")
	}

	// Fetch Authorization Server Metadata from first issuer
	asm, err := FetchAuthorizationServerMetadata(ctx, httpClient, prm.AuthorizationServers[0])
	if err != nil {
		return nil, fmt.Errorf("fetching AS metadata: %w", err)
	}

	return &discoveryResult{
		AuthorizationEndpoint:             asm.AuthorizationEndpoint,
		TokenEndpoint:                     asm.TokenEndpoint,
		Issuer:                            asm.Issuer,
		ScopesSupported:                   prm.ScopesSupported,
		RegistrationEndpoint:              asm.RegistrationEndpoint,
		ClientIDMetadataDocumentSupported: asm.ClientIDMetadataDocumentSupported,
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
	// Check for cached registration
	if storage != nil {
		cached, getErr := storage.GetUpstreamOAuthClient(ctx, issuer, stripPort(downstreamHost))
		if getErr == nil && cached != nil && cached.ClientId != "" {
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

// refreshToken attempts to refresh an expired upstream token.
func (h *UpstreamAuthHandler) refreshToken(
	ctx context.Context,
	token *oauth21proto.UpstreamMCPToken,
) (*oauth21proto.UpstreamMCPToken, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token.RefreshToken},
		"client_id":     {token.Audience}, // CIMD URL as client_id
		"resource":      {token.UpstreamServer},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, token.TokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	tokenResp, err := exchangeToken(h.httpClient, req)
	if err != nil {
		return nil, fmt.Errorf("token refresh: %w", err)
	}

	// Update token in storage
	now := time.Now()
	refreshedToken := &oauth21proto.UpstreamMCPToken{
		UserId:                    token.UserId,
		RouteId:                   token.RouteId,
		UpstreamServer:            token.UpstreamServer,
		AccessToken:               tokenResp.AccessToken,
		RefreshToken:              tokenResp.RefreshToken,
		TokenType:                 tokenResp.TokenType,
		IssuedAt:                  timestamppb.New(now),
		Scopes:                    token.Scopes,
		Audience:                  token.Audience,
		AuthorizationServerIssuer: token.AuthorizationServerIssuer,
		TokenEndpoint:             token.TokenEndpoint,
	}

	if tokenResp.ExpiresIn > 0 {
		refreshedToken.ExpiresAt = timestamppb.New(now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second))
	}

	// Preserve old refresh token if the AS didn't rotate it
	if refreshedToken.RefreshToken == "" {
		refreshedToken.RefreshToken = token.RefreshToken
	}

	if err := h.storage.PutUpstreamMCPToken(ctx, refreshedToken); err != nil {
		return nil, fmt.Errorf("storing refreshed token: %w", err)
	}

	return refreshedToken, nil
}

func (h *UpstreamAuthHandler) getUserID(ctx context.Context, sessionID string) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("no session ID")
	}
	session, err := h.storage.GetSession(ctx, sessionID)
	if err != nil {
		return "", fmt.Errorf("getting session: %w", err)
	}
	userID := session.GetUserId()
	if userID == "" {
		return "", fmt.Errorf("session %s has no user ID", sessionID)
	}
	return userID, nil
}

func (h *UpstreamAuthHandler) getUpstreamServerURL(hostname string) (string, error) {
	info, ok := h.hosts.GetServerHostInfo(hostname)
	if !ok {
		return "", fmt.Errorf("no server info for host %s", hostname)
	}
	if info.UpstreamURL == "" {
		return "", fmt.Errorf("no upstream URL configured for host %s", hostname)
	}
	return info.UpstreamURL, nil
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
	v := url.Values{}
	v.Set("client_id", params.ClientID)
	v.Set("response_type", "code")
	v.Set("redirect_uri", params.RedirectURI)
	if len(params.Scopes) > 0 {
		v.Set("scope", strings.Join(params.Scopes, " "))
	}
	v.Set("state", params.State)
	v.Set("code_challenge", params.CodeChallenge)
	v.Set("code_challenge_method", params.CodeChallengeMethod)
	if params.Resource != "" {
		v.Set("resource", params.Resource)
	}
	return endpoint + "?" + v.Encode()
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

func isNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}
