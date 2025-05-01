package mcp

import (
	"context"
	"crypto/cipher"
	"fmt"
	"net/http"
	"path"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	oteltrace "go.opentelemetry.io/otel/trace"
	googlegrpc "google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

const (
	DefaultPrefix = "/.pomerium/mcp"

	authorizationEndpoint = "/authorize"
	oauthCallbackEndpoint = "/oauth/callback"
	registerEndpoint      = "/register"
	revocationEndpoint    = "/revoke"
	tokenEndpoint         = "/token"
	listRoutesEndpoint    = "/routes"
	connectEndpoint       = "/connect"
)

type Handler struct {
	prefix         string
	trace          oteltrace.TracerProvider
	storage        *Storage
	cipher         cipher.AEAD
	relyingParties *OAuth2Configs
}

func New(
	ctx context.Context,
	prefix string,
	cfg *config.Config,
) (*Handler, error) {
	tracerProvider := trace.NewTracerProvider(ctx, "MCP")

	client, err := getDatabrokerServiceClient(ctx, cfg, tracerProvider)
	if err != nil {
		return nil, fmt.Errorf("databroker client: %w", err)
	}

	cipher, err := getCipher(cfg)
	if err != nil {
		return nil, fmt.Errorf("get cipher: %w", err)
	}

	return &Handler{
		prefix:         prefix,
		trace:          tracerProvider,
		storage:        NewStorage(client),
		cipher:         cipher,
		relyingParties: NewOAuthConfig(cfg, http.DefaultClient),
	}, nil
}

// HandlerFunc returns a http.HandlerFunc that handles the mcp endpoints.
func (srv *Handler) HandlerFunc() http.HandlerFunc {
	r := mux.NewRouter()
	r.Use(cors.New(cors.Options{
		AllowedMethods: []string{http.MethodGet, http.MethodPost, http.MethodOptions},
		AllowedOrigins: []string{"*"},
		AllowedHeaders: []string{"content-type", "mcp-protocol-version"},
	}).Handler)
	r.Methods(http.MethodOptions).HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	r.Path(path.Join(srv.prefix, registerEndpoint)).Methods(http.MethodPost).HandlerFunc(srv.RegisterClient)
	r.Path(path.Join(srv.prefix, authorizationEndpoint)).Methods(http.MethodGet).HandlerFunc(srv.Authorize)
	r.Path(path.Join(srv.prefix, oauthCallbackEndpoint)).Methods(http.MethodGet).HandlerFunc(srv.OAuthCallback)
	r.Path(path.Join(srv.prefix, tokenEndpoint)).Methods(http.MethodPost).HandlerFunc(srv.Token)
	r.Path(path.Join(srv.prefix, listRoutesEndpoint)).Methods(http.MethodGet).HandlerFunc(srv.ListRoutes)
	r.Path(path.Join(srv.prefix, connectEndpoint)).Methods(http.MethodGet).HandlerFunc(srv.Connect)

	return r.ServeHTTP
}

var outboundGRPCConnection = new(grpc.CachedOutboundGRPClientConn)

func getDatabrokerServiceClient(
	ctx context.Context,
	cfg *config.Config,
	tracerProvider oteltrace.TracerProvider,
) (databroker.DataBrokerServiceClient, error) {
	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, fmt.Errorf("shared key: %w", err)
	}

	dataBrokerConn, err := outboundGRPCConnection.Get(ctx, &grpc.OutboundOptions{
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
