package proxy

import (
	"context"
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/authenticateflow"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	oteltrace "go.opentelemetry.io/otel/trace"
	googlegrpc "google.golang.org/grpc"
)

var outboundGRPCConnection = new(grpc.CachedOutboundGRPClientConn)

type authenticateFlow interface {
	AuthenticateSignInURL(ctx context.Context, queryParams url.Values, redirectURL *url.URL, idpID string) (string, error)
	Callback(w http.ResponseWriter, r *http.Request, route *config.Policy) error
}

type proxyState struct {
	authenticateURL          *url.URL
	authenticateDashboardURL *url.URL
	authenticateSigninURL    *url.URL
	authenticateRefreshURL   *url.URL

	sharedKey                           []byte
	sessionStore                        *config.SessionStore
	dataBrokerClient                    databroker.DataBrokerServiceClient
	programmaticRedirectDomainWhitelist []string
	authenticateFlow                    authenticateFlow
}

func newProxyStateFromConfig(ctx context.Context, tracerProvider oteltrace.TracerProvider, cfg *config.Config) (*proxyState, error) {
	err := ValidateOptions(cfg.Options)
	if err != nil {
		return nil, err
	}

	state := new(proxyState)

	state.authenticateURL, err = cfg.Options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}
	state.authenticateDashboardURL = state.authenticateURL.ResolveReference(&url.URL{Path: "/.pomerium/"})
	state.authenticateSigninURL = state.authenticateURL.ResolveReference(&url.URL{Path: signinURL})
	state.authenticateRefreshURL = state.authenticateURL.ResolveReference(&url.URL{Path: refreshURL})

	state.sharedKey, err = cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	state.sessionStore, err = config.NewSessionStore(cfg.Options)
	if err != nil {
		return nil, err
	}

	dataBrokerConn, err := outboundGRPCConnection.Get(ctx, &grpc.OutboundOptions{
		OutboundPort:   cfg.OutboundPort,
		InstallationID: cfg.Options.InstallationID,
		ServiceName:    cfg.Options.Services,
		SignedJWTKey:   state.sharedKey,
	}, googlegrpc.WithStatsHandler(otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(tracerProvider))))
	if err != nil {
		return nil, err
	}
	state.dataBrokerClient = databroker.NewDataBrokerServiceClient(dataBrokerConn)

	state.programmaticRedirectDomainWhitelist = cfg.Options.ProgrammaticRedirectDomainWhitelist

	if cfg.Options.UseStatelessAuthenticateFlow() {
		state.authenticateFlow, err = authenticateflow.NewStateless(ctx, tracerProvider,
			cfg, state.sessionStore, nil, nil, nil)
	} else {
		state.authenticateFlow, err = authenticateflow.NewStateful(ctx, tracerProvider, cfg, state.sessionStore)
	}
	if err != nil {
		return nil, err
	}

	return state, nil
}
