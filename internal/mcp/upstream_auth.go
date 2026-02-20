package mcp

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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
	serverInfo, err := h.getServerInfo(hostname)
	if err != nil {
		return nil, fmt.Errorf("getting server info: %w", err)
	}

	// The resource URL is the actual URL the client was trying to access (with path).
	// This is used for PRM discovery/validation and the OAuth resource parameter.
	// The base upstreamServer URL is used for token storage keys (must match getAutoDiscoveryToken).
	resourceURL := stripQueryFromURL(originalURL)

	userID, err := h.getUserID(ctx, routeCtx.SessionID)
	if err != nil {
		return nil, fmt.Errorf("getting user ID: %w", err)
	}

	setup, err := runUpstreamOAuthSetup(ctx, h.httpClient, resourceURL, host,
		WithStorage(h.storage),
		WithWWWAuthenticate(wwwAuth),
		WithFallbackAuthorizationURL(serverInfo.AuthorizationServerURL),
	)
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
		UpstreamServer:            serverInfo.UpstreamURL,
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
		ResourceParam:             setup.Discovery.Resource,
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

// refreshToken attempts to refresh an expired upstream token.
func (h *UpstreamAuthHandler) refreshToken(
	ctx context.Context,
	token *oauth21proto.UpstreamMCPToken,
) (*oauth21proto.UpstreamMCPToken, error) {
	// Use ResourceParam for the RFC 8707 resource indicator.
	// Falls back to UpstreamServer for tokens stored before ResourceParam was added.
	resourceParam := token.GetResourceParam()
	if resourceParam == "" {
		resourceParam = token.UpstreamServer
	}
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {token.RefreshToken},
		"client_id":     {token.Audience}, // CIMD URL as client_id
	}
	if resourceParam != "" {
		data.Set("resource", resourceParam)
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
		ResourceParam:             token.ResourceParam,
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
	info, err := h.getServerInfo(hostname)
	if err != nil {
		return "", err
	}
	return info.UpstreamURL, nil
}

func (h *UpstreamAuthHandler) getServerInfo(hostname string) (ServerHostInfo, error) {
	info, ok := h.hosts.GetServerHostInfo(hostname)
	if !ok {
		return ServerHostInfo{}, fmt.Errorf("no server info for host %s", hostname)
	}
	if info.UpstreamURL == "" {
		return ServerHostInfo{}, fmt.Errorf("no upstream URL configured for host %s", hostname)
	}
	return info, nil
}

func isNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}
