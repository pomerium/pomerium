// Package authorize is a pomerium service that is responsible for determining
// if a given request should be authorized (AuthZ).
package authorize

import (
	"context"
	"fmt"
	"html/template"
	"sync"
	"sync/atomic"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type atomicOptions struct {
	value atomic.Value
}

func (a *atomicOptions) Load() *config.Options {
	return a.value.Load().(*config.Options)
}

func (a *atomicOptions) Store(options *config.Options) {
	a.value.Store(options)
}

type atomicMarshalUnmarshaler struct {
	value atomic.Value
}

func (a *atomicMarshalUnmarshaler) Load() encoding.MarshalUnmarshaler {
	return a.value.Load().(encoding.MarshalUnmarshaler)
}

func (a *atomicMarshalUnmarshaler) Store(encoder encoding.MarshalUnmarshaler) {
	a.value.Store(encoder)
}

// Authorize struct holds
type Authorize struct {
	pe    *evaluator.Evaluator
	store *evaluator.Store

	currentOptions atomicOptions
	currentEncoder atomicMarshalUnmarshaler
	templates      *template.Template

	dataBrokerClient databroker.DataBrokerServiceClient

	dataBrokerDataLock sync.RWMutex
	dataBrokerData     evaluator.DataBrokerData
}

// New validates and creates a new Authorize service from a set of config options.
func New(opts *config.Options) (*Authorize, error) {
	if err := validateOptions(opts); err != nil {
		return nil, fmt.Errorf("authorize: bad options: %w", err)
	}

	dataBrokerConn, err := grpc.NewGRPCClientConn(
		&grpc.Options{
			Addr:                    opts.DataBrokerURL,
			OverrideCertificateName: opts.OverrideCertificateName,
			CA:                      opts.CA,
			CAFile:                  opts.CAFile,
			RequestTimeout:          opts.GRPCClientTimeout,
			ClientDNSRoundRobin:     opts.GRPCClientDNSRoundRobin,
			WithInsecure:            opts.GRPCInsecure,
			ServiceName:             opts.Services,
		})
	if err != nil {
		return nil, fmt.Errorf("authorize: error creating cache connection: %w", err)
	}

	a := Authorize{
		store:            evaluator.NewStore(),
		templates:        template.Must(frontend.NewTemplates()),
		dataBrokerClient: databroker.NewDataBrokerServiceClient(dataBrokerConn),
		dataBrokerData:   make(evaluator.DataBrokerData),
	}

	var host string
	if opts.AuthenticateURL != nil {
		host = opts.AuthenticateURL.Host
	}
	encoder, err := jws.NewHS256Signer([]byte(opts.SharedKey), host)
	if err != nil {
		return nil, err
	}
	a.currentEncoder.Store(encoder)
	a.currentOptions.Store(new(config.Options))
	return &a, nil
}

func validateOptions(o *config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("bad shared_secret: %w", err)
	}
	if err := urlutil.ValidateURL(o.AuthenticateURL); err != nil {
		return fmt.Errorf("invalid 'AUTHENTICATE_SERVICE_URL': %w", err)
	}
	return nil
}

// newPolicyEvaluator returns an policy evaluator.
func newPolicyEvaluator(opts *config.Options, store *evaluator.Store) (*evaluator.Evaluator, error) {
	metrics.AddPolicyCountCallback("pomerium-authorize", func() int64 {
		return int64(len(opts.Policies))
	})
	ctx := context.Background()
	_, span := trace.StartSpan(ctx, "authorize.newPolicyEvaluator")
	defer span.End()
	return evaluator.New(opts, store)
}

// OnConfigChange updates internal structures based on config.Options
func (a *Authorize) OnConfigChange(cfg *config.Config) {
	log.Info().Str("checksum", fmt.Sprintf("%x", cfg.Options.Checksum())).Msg("authorize: updating options")
	a.currentOptions.Store(cfg.Options)
	pe, err := newPolicyEvaluator(cfg.Options, a.store)
	if err != nil {
		log.Error().Err(err).Msg("authorize: failed to update policy with options")
		return
	}
	a.pe = pe
}
