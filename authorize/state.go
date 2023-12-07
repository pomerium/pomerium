package authorize

import (
	"context"
	"fmt"
	"net/url"

	googlegrpc "google.golang.org/grpc"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/authenticateflow"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

var outboundGRPCConnection = new(grpc.CachedOutboundGRPClientConn)

type authenticateFlow interface {
	AuthenticateSignInURL(ctx context.Context, queryParams url.Values, redirectURL *url.URL, idpID string) (string, error)
}

type authorizeState struct {
	sharedKey                  []byte
	evaluator                  *evaluator.Evaluator
	dataBrokerClientConnection *googlegrpc.ClientConn
	dataBrokerClient           databroker.DataBrokerServiceClient
	auditEncryptor             *protoutil.Encryptor
	sessionStore               *config.SessionStore
	authenticateFlow           authenticateFlow
}

func newAuthorizeStateFromConfig(
	cfg *config.Config, store *store.Store, previousPolicyEvaluator *evaluator.Evaluator,
) (*authorizeState, error) {
	if err := validateOptions(cfg.Options); err != nil {
		return nil, fmt.Errorf("authorize: bad options: %w", err)
	}

	state := new(authorizeState)

	var err error

	state.evaluator, err = newPolicyEvaluator(cfg.Options, store, previousPolicyEvaluator)
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

	cc, err := outboundGRPCConnection.Get(context.Background(), &grpc.OutboundOptions{
		OutboundPort:   cfg.OutboundPort,
		InstallationID: cfg.Options.InstallationID,
		ServiceName:    cfg.Options.Services,
		SignedJWTKey:   sharedKey,
	})
	if err != nil {
		return nil, fmt.Errorf("authorize: error creating databroker connection: %w", err)
	}
	state.dataBrokerClientConnection = cc
	state.dataBrokerClient = databroker.NewDataBrokerServiceClient(cc)

	auditKey, err := cfg.Options.GetAuditKey()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid audit key: %w", err)
	}
	if auditKey != nil {
		state.auditEncryptor = protoutil.NewEncryptor(auditKey)
	}

	state.sessionStore, err = config.NewSessionStore(cfg.Options)
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid session store: %w", err)
	}

	state.authenticateFlow, err = authenticateflow.NewStateless(cfg, nil, nil, nil, nil)
	if err != nil {
		return nil, err
	}

	return state, nil
}
