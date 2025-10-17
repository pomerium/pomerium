package proxy

import (
	"context"
	"net/http"
	"net/url"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	oteltrace "go.opentelemetry.io/otel/trace"
	googlegrpc "google.golang.org/grpc"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/authenticateflow"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

type authenticateFlow interface {
	AuthenticateSignInURL(ctx context.Context, queryParams url.Values, redirectURL *url.URL, idpID string, additionalHosts []string) (string, error)
	Callback(w http.ResponseWriter, r *http.Request) error
}

type proxyState struct {
	authenticateURL          *url.URL
	authenticateDashboardURL *url.URL
	authenticateSigninURL    *url.URL

	sharedKey                           []byte
	sessionStore                        *config.SessionStore
	dataBrokerClient                    databroker.DataBrokerServiceClient
	programmaticRedirectDomainWhitelist []string
	authenticateFlow                    authenticateFlow
	incomingIDPTokenSessionCreator      config.IncomingIDPTokenSessionCreator
}

func newProxyStateFromConfig(ctx context.Context, tracerProvider oteltrace.TracerProvider, cfg *config.Config, outboundGrpcConn *grpc.CachedOutboundGRPClientConn) (*proxyState, error) {
	err := ValidateOptions(cfg.Options)
	if err != nil {
		return nil, err
	}

	state := new(proxyState)

	state.authenticateURL, err = cfg.Options.GetAuthenticateURL()
	if err != nil {
		return nil, err
	}
	state.authenticateDashboardURL = state.authenticateURL.ResolveReference(&url.URL{Path: endpoints.PathPomeriumDashboard + "/"})
	state.authenticateSigninURL = state.authenticateURL.ResolveReference(&url.URL{Path: endpoints.PathPomeriumSignIn})

	state.sharedKey, err = cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	state.sessionStore, err = config.NewSessionStore(cfg.Options)
	if err != nil {
		return nil, err
	}

	dataBrokerConn, err := outboundGrpcConn.Get(ctx, &grpc.OutboundOptions{
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
			cfg, state.sessionStore, nil, nil, nil, outboundGrpcConn)
	} else {
		state.authenticateFlow, err = authenticateflow.NewStateful(ctx, tracerProvider, cfg, state.sessionStore, outboundGrpcConn)
	}
	if err != nil {
		return nil, err
	}

	state.incomingIDPTokenSessionCreator = config.NewIncomingIDPTokenSessionCreator(
		tracerProvider,
		func(ctx context.Context, recordType, recordID string) (*databroker.Record, error) {
			return storage.GetDataBrokerRecord(ctx, recordType, recordID, 0)
		},
		func(ctx context.Context, records []*databroker.Record) error {
			_, err := state.dataBrokerClient.Put(ctx, &databroker.PutRequest{
				Records: records,
			})
			if err != nil {
				return err
			}
			storage.InvalidateCacheForDataBrokerRecords(ctx, records...)
			return err
		},
	)

	return state, nil
}
