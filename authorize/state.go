package authorize

import (
	"context"
	"fmt"

	googlegrpc "google.golang.org/grpc"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

var outboundGRPCConnection = new(grpc.CachedOutboundGRPClientConn)

type authorizeState struct {
	sharedKey                  []byte
	evaluator                  *evaluator.Evaluator
	encoder                    encoding.MarshalUnmarshaler
	dataBrokerClientConnection *googlegrpc.ClientConn
	dataBrokerClient           databroker.DataBrokerServiceClient
	auditEncryptor             *protoutil.Encryptor
}

func newAuthorizeStateFromConfig(cfg *config.Config, store *store.Store) (*authorizeState, error) {
	if err := validateOptions(cfg.Options); err != nil {
		return nil, fmt.Errorf("authorize: bad options: %w", err)
	}

	state := new(authorizeState)

	var err error

	state.evaluator, err = newPolicyEvaluator(cfg.Options, store)
	if err != nil {
		return nil, fmt.Errorf("authorize: failed to update policy with options: %w", err)
	}

	state.sharedKey, err = cfg.Options.GetSharedKey()
	if err != nil {
		return nil, err
	}

	state.encoder, err = jws.NewHS256Signer(state.sharedKey)
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

	return state, nil
}
