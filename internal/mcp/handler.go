package mcp

import (
	"context"
	"crypto/cipher"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/singleflight"
	googlegrpc "google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

const (
	WellKnownAuthorizationServerEndpoint = "/.well-known/oauth-authorization-server"
	WellKnownProtectedResourceEndpoint   = "/.well-known/oauth-protected-resource"

	DefaultPrefix = endpoints.PathPomeriumMCP

	authorizationEndpoint = "/authorize"
	registerEndpoint      = "/register"
	revocationEndpoint    = "/revoke"
	tokenEndpoint         = "/token"
	listRoutesEndpoint    = "/routes"
	connectEndpoint       = "/connect"
	disconnectEndpoint    = "/routes/disconnect"

	// OAuth callback endpoints - split for clarity between Pomerium acting as server vs client
	// serverOAuthCallbackEndpoint is used when Pomerium acts as an OAuth 2.1 authorization server
	// and MCP clients (like Claude) authenticate with Pomerium.
	serverOAuthCallbackEndpoint = "/server/oauth/callback"
	// clientOAuthCallbackEndpoint is used when Pomerium acts as an OAuth 2.1 client
	// to remote MCP servers' authorization servers (auto-discovery/proxy mode).
	clientOAuthCallbackEndpoint = "/client/oauth/callback"
)

// AuthenticatorGetter is a function that returns an authenticator for the given IdP ID.
type AuthenticatorGetter func(ctx context.Context, idpID string) (identity.Authenticator, error)

type Handler struct {
	prefix                  string
	trace                   oteltrace.TracerProvider
	storage                 HandlerStorage
	cipher                  cipher.AEAD
	hosts                   *HostInfo
	hostsSingleFlight       singleflight.Group
	clientMetadataFetcher   *ClientMetadataFetcher
	getAuthenticator        AuthenticatorGetter
	sessionExpiry           time.Duration
	httpClient              *http.Client // for upstream discovery fetches
	asMetadataDomainMatcher *DomainMatcher
	allowPRMSameDomainOrigin bool
}

// HandlerOption is a functional option for configuring a Handler.
type HandlerOption func(*Handler)

// WithClientMetadataFetcher sets the client metadata fetcher.
// This is primarily useful for testing.
func WithClientMetadataFetcher(fetcher *ClientMetadataFetcher) HandlerOption {
	return func(h *Handler) {
		h.clientMetadataFetcher = fetcher
	}
}

// WithAuthenticatorGetter sets the authenticator getter function.
// This is used to refresh upstream OAuth tokens when recreating sessions.
func WithAuthenticatorGetter(getter AuthenticatorGetter) HandlerOption {
	return func(h *Handler) {
		h.getAuthenticator = getter
	}
}

// WithSessionExpiry sets the session expiry duration.
// This overrides the default from config.Options.CookieExpire.
func WithSessionExpiry(d time.Duration) HandlerOption {
	return func(h *Handler) {
		h.sessionExpiry = d
	}
}

// WithHTTPClient sets the HTTP client used for upstream discovery fetches.
func WithHTTPClient(client *http.Client) HandlerOption {
	return func(h *Handler) {
		h.httpClient = client
	}
}

// SetClientMetadataFetcher replaces the client metadata fetcher.
// This is exposed for testing purposes only.
func (h *Handler) SetClientMetadataFetcher(fetcher *ClientMetadataFetcher) {
	h.clientMetadataFetcher = fetcher
}

func New(
	ctx context.Context,
	prefix string,
	cfg *config.Config,
	outboundGrpcConn *grpc.CachedOutboundGRPClientConn,
	opts ...HandlerOption,
) (*Handler, error) {
	tracerProvider := trace.NewTracerProvider(ctx, "MCP")

	client, err := getDatabrokerServiceClient(ctx, cfg, tracerProvider, outboundGrpcConn)
	if err != nil {
		return nil, fmt.Errorf("databroker client: %w", err)
	}

	cipher, err := getCipher(cfg)
	if err != nil {
		return nil, fmt.Errorf("get cipher: %w", err)
	}

	// Create domain matcher from config for client ID metadata URL validation
	domainMatcher := NewDomainMatcher(cfg.Options.MCPAllowedClientIDDomains)

	// Use the SSRF-safe client by default; skip for testing environments
	// where test servers run on localhost.
	var cimdHTTPClient *http.Client
	if cfg.Options.InsecureSkipMCPMetadataSSRFCheck {
		cimdHTTPClient = http.DefaultClient
	} else {
		cimdHTTPClient = NewSSRFSafeClient()
	}

	asDomainMatcher := NewDomainMatcher(cfg.Options.MCPAllowedASMetadataDomains)

	h := &Handler{
		prefix:                  prefix,
		trace:                   tracerProvider,
		storage:                 NewStorage(client),
		cipher:                  cipher,
		hosts:                   NewHostInfo(cfg, http.DefaultClient),
		clientMetadataFetcher:   NewClientMetadataFetcher(cimdHTTPClient, domainMatcher),
		sessionExpiry:           cfg.Options.CookieExpire,
		httpClient:              http.DefaultClient,
		asMetadataDomainMatcher: asDomainMatcher,
		allowPRMSameDomainOrigin: cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagMCPAllowPRMSameDomainOrigin),
	}

	for _, opt := range opts {
		opt(h)
	}

	return h, nil
}

// HandlerFunc returns a http.HandlerFunc that handles the mcp endpoints.
func (h *Handler) HandlerFunc() http.HandlerFunc {
	r := mux.NewRouter()
	// CORS for OAuth endpoints (token, registration, etc.).
	// "authorization" is needed because the token endpoint supports
	// client_secret_basic authentication (RFC 6749 §2.3.1, OAuth 2.1 §3.2).
	r.Use(cors.New(cors.Options{
		AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodOptions},
		AllowedOrigins: []string{"*"},
		AllowedHeaders: []string{"authorization", "content-type", "mcp-protocol-version"},
	}).Handler)
	r.Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	r.Path(path.Join(h.prefix, registerEndpoint)).Methods(http.MethodPost).HandlerFunc(h.RegisterClient)
	r.Path(path.Join(h.prefix, authorizationEndpoint)).Methods(http.MethodGet).HandlerFunc(h.Authorize)
	r.Path(path.Join(h.prefix, serverOAuthCallbackEndpoint)).Methods(http.MethodGet).HandlerFunc(h.OAuthCallback)
	r.Path(path.Join(h.prefix, clientOAuthCallbackEndpoint)).Methods(http.MethodGet).HandlerFunc(h.ClientOAuthCallback)
	r.Path(path.Join(h.prefix, clientMetadataEndpoint)).Methods(http.MethodGet).HandlerFunc(h.ClientIDMetadata)
	r.Path(path.Join(h.prefix, tokenEndpoint)).Methods(http.MethodPost).HandlerFunc(h.Token)
	r.Path(path.Join(h.prefix, listRoutesEndpoint)).Methods(http.MethodGet).HandlerFunc(h.ListRoutes)
	r.Path(path.Join(h.prefix, connectEndpoint)).Methods(http.MethodGet).HandlerFunc(h.ConnectGet)
	r.Path(path.Join(h.prefix, disconnectEndpoint)).Methods(http.MethodPost).HandlerFunc(h.DisconnectRoutes)

	return r.ServeHTTP
}

func getDatabrokerServiceClient(
	ctx context.Context,
	cfg *config.Config,
	tracerProvider oteltrace.TracerProvider,
	outboundGrpcConn *grpc.CachedOutboundGRPClientConn,
) (databroker.DataBrokerServiceClient, error) {
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
	return databroker.NewDataBrokerServiceClient(dataBrokerConn), nil
}
