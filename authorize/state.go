package authorize

import (
	"context"
	"fmt"
	"net/url"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	oteltrace "go.opentelemetry.io/otel/trace"
	googlegrpc "google.golang.org/grpc"

	"github.com/pomerium/datasource/pkg/directory"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/authenticateflow"
	"github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/ssh"
	"github.com/pomerium/pomerium/pkg/storage"
)

var outboundGRPCConnection = new(grpc.CachedOutboundGRPClientConn)

type authenticateFlow interface {
	AuthenticateSignInURL(ctx context.Context, queryParams url.Values, redirectURL *url.URL, idpID string, additionalLoginHosts []string) (string, error)
}

type authorizeState struct {
	sharedKey                  []byte
	evaluator                  *evaluator.Evaluator
	dataBrokerClientConnection *googlegrpc.ClientConn
	dataBrokerClient           databroker.DataBrokerServiceClient
	sessionStore               *config.SessionStore
	idpTokenSessionCreator     config.IncomingIDPTokenSessionCreator
	authenticateFlow           authenticateFlow
	syncQueriers               map[string]storage.Querier
	mcp                        *mcp.Handler
	ssh                        *ssh.StreamManager
}

func newAuthorizeStateFromConfig(
	ctx context.Context,
	previousState *authorizeState,
	tracerProvider oteltrace.TracerProvider,
	cfg *config.Config,
	store *store.Store,
) (*authorizeState, error) {
	if err := validateOptions(cfg.Options); err != nil {
		return nil, fmt.Errorf("authorize: bad options: %w", err)
	}

	state := new(authorizeState)

	var err error
	var previousEvaluator *evaluator.Evaluator
	if previousState != nil {
		previousEvaluator = previousState.evaluator
	}

	var evaluatorOptions []evaluator.Option
	if cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagMCP) {
		mcp, err := mcp.New(ctx, mcp.DefaultPrefix, cfg)
		if err != nil {
			return nil, fmt.Errorf("authorize: failed to create mcp handler: %w", err)
		}
		state.mcp = mcp
		evaluatorOptions = append(evaluatorOptions, evaluator.WithMCPAccessTokenProvider(mcp))
	}

	state.ssh = ssh.NewStreamManager(nil) // XXX

	state.evaluator, err = newPolicyEvaluator(ctx, cfg.Options, store, previousEvaluator, evaluatorOptions...)
	if err != nil {
		return nil, fmt.Errorf("authorize: failed to update policy with options: %w", err)
	}

	state.sharedKey, err = cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	cc, err := outboundGRPCConnection.Get(ctx, &grpc.OutboundOptions{
		OutboundPort:   cfg.OutboundPort,
		InstallationID: cfg.Options.InstallationID,
		ServiceName:    cfg.Options.Services,
		SignedJWTKey:   sharedKey,
	}, googlegrpc.WithStatsHandler(otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(tracerProvider))))
	if err != nil {
		return nil, fmt.Errorf("authorize: error creating databroker connection: %w", err)
	}
	state.dataBrokerClientConnection = cc
	state.dataBrokerClient = databroker.NewDataBrokerServiceClient(cc)

	state.sessionStore, err = config.NewSessionStore(cfg.Options)
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid session store: %w", err)
	}
	state.idpTokenSessionCreator = config.NewIncomingIDPTokenSessionCreator(
		func(ctx context.Context, recordType, recordID string) (*databroker.Record, error) {
			return storage.GetDataBrokerRecord(ctx, recordType, recordID, 0)
		},
		func(ctx context.Context, records []*databroker.Record) error {
			res, err := state.dataBrokerClient.Put(ctx, &databroker.PutRequest{
				Records: records,
			})
			if err != nil {
				return err
			}
			storage.InvalidateCacheForDataBrokerRecords(ctx, res.Records...)
			return nil
		},
	)

	if cfg.Options.UseStatelessAuthenticateFlow() {
		state.authenticateFlow, err = authenticateflow.NewStateless(ctx, tracerProvider, cfg, nil, nil, nil, nil)
	} else {
		state.authenticateFlow, err = authenticateflow.NewStateful(ctx, tracerProvider, cfg, nil)
	}
	if err != nil {
		return nil, err
	}

	state.syncQueriers = make(map[string]storage.Querier)
	if previousState != nil {
		if previousState.dataBrokerClientConnection == state.dataBrokerClientConnection {
			state.syncQueriers = previousState.syncQueriers
		} else {
			for _, v := range previousState.syncQueriers {
				v.Stop()
			}
		}
	}
	if cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagAuthorizeUseSyncedData) {
		for _, recordType := range []string{
			grpcutil.GetTypeURL(new(session.Session)),
			grpcutil.GetTypeURL(new(user.User)),
			grpcutil.GetTypeURL(new(user.ServiceAccount)),
			directory.GroupRecordType,
			directory.UserRecordType,
		} {
			if _, ok := state.syncQueriers[recordType]; !ok {
				state.syncQueriers[recordType] = storage.NewSyncQuerier(state.dataBrokerClient, recordType)
			}
		}
	}

	return state, nil
}
