// Package authorize is a pomerium service that is responsible for determining
// if a given request should be authorized (AuthZ).
package authorize

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	envoy_eds_v3 "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/metric"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	googlegrpc "google.golang.org/grpc"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/ssh"
	"github.com/pomerium/pomerium/pkg/ssh/code"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// Authorize struct holds
type Authorize struct {
	logDuration metric.Int64Histogram

	state         atomic.Pointer[authorizeState]
	store         *store.Store
	currentConfig atomic.Pointer[config.Config]
	accessTracker *AccessTracker
	ssh           *ssh.StreamManager
	policyIndexer *ssh.InMemoryPolicyIndexer

	tracerProvider oteltrace.TracerProvider
	tracer         oteltrace.Tracer

	outboundGrpcConn grpc.CachedOutboundGRPClientConn
}

// New validates and creates a new Authorize service from a set of config options.
func New(ctx context.Context, cfg *config.Config) (*Authorize, error) {
	tracerProvider := trace.NewTracerProvider(ctx, "Authorize")
	tracer := tracerProvider.Tracer(trace.PomeriumCoreTracer)

	a := &Authorize{
		logDuration: metrics.Int64Histogram("authorize.log.duration",
			metric.WithDescription("Duration of authorize log execution."),
			metric.WithUnit("ms")),

		store:          store.New(),
		tracerProvider: tracerProvider,
		tracer:         tracer,
	}
	a.currentConfig.Store(cfg)
	state, err := newAuthorizeStateFromConfig(ctx, nil, tracerProvider, cfg, a.store, &a.outboundGrpcConn)
	if err != nil {
		return nil, err
	}
	a.state.Store(state)

	codeIssuer := code.NewIssuer(ctx, a)
	a.accessTracker = NewAccessTracker(a, accessTrackerMaxSize, accessTrackerDebouncePeriod)
	a.policyIndexer = ssh.NewInMemoryPolicyIndexer(a)
	a.ssh = ssh.NewStreamManager(ctx, ssh.NewAuth(a, &a.currentConfig, a.tracerProvider, codeIssuer), a.policyIndexer, cfg)
	return a, nil
}

func (a *Authorize) RegisterGRPCServices(server *googlegrpc.Server) {
	envoy_service_auth_v3.RegisterAuthorizationServer(server, a)
	extensions_ssh.RegisterStreamManagementServer(server, a)
	envoy_eds_v3.RegisterEndpointDiscoveryServiceServer(server, a.ssh)
}

// GetDataBrokerServiceClient returns the current DataBrokerServiceClient.
func (a *Authorize) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return a.state.Load().dataBrokerClient
}

// Run runs the authorize service.
func (a *Authorize) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return a.ssh.Run(ctx)
	})
	eg.Go(func() error {
		return a.policyIndexer.Run(ctx)
	})
	eg.Go(func() error {
		a.accessTracker.Run(ctx)
		return nil
	})
	return eg.Wait()
}

func validateOptions(o *config.Options) error {
	sharedKey, err := o.GetSharedKey()
	if err != nil {
		return fmt.Errorf("authorize: bad 'SHARED_SECRET': %w", err)
	}
	if _, err := cryptutil.NewAEADCipher(sharedKey); err != nil {
		return fmt.Errorf("authorize: bad 'SHARED_SECRET': %w", err)
	}
	return nil
}

// newPolicyEvaluator returns an policy evaluator.
func newPolicyEvaluator(
	ctx context.Context,
	opts *config.Options, store *store.Store, previous *evaluator.Evaluator,
	evaluatorOpts ...evaluator.Option,
) (*evaluator.Evaluator, error) {
	metrics.AddPolicyCountCallback("pomerium-authorize", func() int64 {
		return int64(opts.NumPolicies())
	})
	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("service", "authorize")
	})
	ctx, span := trace.Continue(ctx, "authorize.newPolicyEvaluator")
	defer span.End()

	clientCA, err := opts.DownstreamMTLS.GetCA()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid client CA: %w", err)
	}

	clientCRL, err := opts.DownstreamMTLS.GetCRL()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid client CRL: %w", err)
	}

	authenticateURL, err := opts.GetInternalAuthenticateURL()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid authenticate url: %w", err)
	}

	signingKey, err := opts.GetSigningKey()
	if err != nil {
		return nil, fmt.Errorf("authorize: invalid signing key: %w", err)
	}

	// It is important to add an invalid_client_certificate rule even when the
	// mTLS enforcement behavior is set to reject connections at the listener
	// level, because of the per-route TLSDownstreamClientCA setting.
	addDefaultClientCertificateRule := opts.HasAnyDownstreamMTLSClientCA() &&
		opts.DownstreamMTLS.GetEnforcement() != config.MTLSEnforcementPolicy

	clientCertConstraints, err := evaluator.ClientCertConstraintsFromConfig(&opts.DownstreamMTLS)
	if err != nil {
		return nil, fmt.Errorf(
			"authorize: internal error: couldn't build client cert constraints: %w", err)
	}

	allPolicies := slices.Collect(opts.GetAllPolicies())
	evaluatorOpts = append([]evaluator.Option{
		evaluator.WithPolicies(allPolicies),
		evaluator.WithClientCA(clientCA),
		evaluator.WithAddDefaultClientCertificateRule(addDefaultClientCertificateRule),
		evaluator.WithClientCRL(clientCRL),
		evaluator.WithClientCertConstraints(clientCertConstraints),
		evaluator.WithSigningKey(signingKey),
		evaluator.WithAuthenticateURL(authenticateURL.String()),
		evaluator.WithGoogleCloudServerlessAuthenticationServiceAccount(opts.GetGoogleCloudServerlessAuthenticationServiceAccount()),
		evaluator.WithJWTClaimsHeaders(opts.JWTClaimsHeaders),
		evaluator.WithJWTGroupsFilter(opts.JWTGroupsFilter),
		evaluator.WithDefaultJWTIssuerFormat(opts.JWTIssuerFormat),
	}, evaluatorOpts...)
	return evaluator.New(ctx, store, previous, evaluatorOpts...)
}

// OnConfigChange updates internal structures based on config.Options
func (a *Authorize) OnConfigChange(ctx context.Context, cfg *config.Config) {
	currentState := a.state.Load()
	a.currentConfig.Store(cfg)
	if newState, err := newAuthorizeStateFromConfig(ctx, currentState, a.tracerProvider, cfg, a.store, &a.outboundGrpcConn); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize: error updating state")
	} else {
		a.state.Store(newState)
	}
	a.ssh.OnConfigChange(cfg)
}
