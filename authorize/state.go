package authorize

import (
	"encoding/base64"
	"fmt"
	"sync/atomic"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type authorizeState struct {
	// sharedSecret is the secret to encrypt and authenticate data shared between services
	sharedSecret []byte

	evaluator        *evaluator.Evaluator
	encoder          encoding.MarshalUnmarshaler
	dataBrokerClient databroker.DataBrokerServiceClient
}

func newAuthorizeStateFromConfig(cfg *config.Config, store *evaluator.Store) (*authorizeState, error) {
	if err := validateOptions(cfg.Options); err != nil {
		return nil, fmt.Errorf("authorize: bad options: %w", err)
	}

	state := new(authorizeState)

	var err error

	state.evaluator, err = newPolicyEvaluator(cfg.Options, store)
	if err != nil {
		return nil, fmt.Errorf("authorize: failed to update policy with options: %w", err)
	}

	state.encoder, err = jws.NewHS256Signer([]byte(cfg.Options.SharedKey))
	if err != nil {
		return nil, err
	}

	state.sharedSecret, _ = base64.StdEncoding.DecodeString(cfg.Options.SharedKey)
	urls, err := cfg.Options.GetDataBrokerURLs()
	if err != nil {
		return nil, err
	}

	cc, err := grpc.GetGRPCClientConn("databroker", &grpc.Options{
		Addrs:                   urls,
		OverrideCertificateName: cfg.Options.OverrideCertificateName,
		CA:                      cfg.Options.CA,
		CAFile:                  cfg.Options.CAFile,
		RequestTimeout:          cfg.Options.GRPCClientTimeout,
		ClientDNSRoundRobin:     cfg.Options.GRPCClientDNSRoundRobin,
		WithInsecure:            cfg.Options.GRPCInsecure,
		ServiceName:             cfg.Options.Services,
		SignedJWTKey:            state.sharedSecret,
	})
	if err != nil {
		return nil, fmt.Errorf("authorize: error creating databroker connection: %w", err)
	}
	state.dataBrokerClient = databroker.NewDataBrokerServiceClient(cc)

	return state, nil
}

type atomicAuthorizeState struct {
	value atomic.Value
}

func newAtomicAuthorizeState(state *authorizeState) *atomicAuthorizeState {
	aas := new(atomicAuthorizeState)
	aas.Store(state)
	return aas
}

func (aas *atomicAuthorizeState) Load() *authorizeState {
	return aas.value.Load().(*authorizeState)
}

func (aas *atomicAuthorizeState) Store(state *authorizeState) {
	aas.value.Store(state)
}
