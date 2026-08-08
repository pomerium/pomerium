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
	envoy_service_ratelimit_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ratelimit/v3"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"
	googlegrpc "google.golang.org/grpc"

	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	extensions_event_sinks_grpc "github.com/pomerium/envoy-custom/api/extensions/health_check/event_sinks/grpc"
	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/internal/store"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/recording"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/secrets"
	"github.com/pomerium/pomerium/pkg/secrets/resolver"
	"github.com/pomerium/pomerium/pkg/ssh"
	ssh_cli "github.com/pomerium/pomerium/pkg/ssh/cli"
	"github.com/pomerium/pomerium/pkg/ssh/code"
	"github.com/pomerium/pomerium/pkg/ssh/ratelimit"
	"github.com/pomerium/pomerium/pkg/ssh/tui/style"
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
	policyIndexer ssh.PolicyIndexer

	tracerProvider oteltrace.TracerProvider
	tracer         oteltrace.Tracer

	outboundGrpcConn grpc.CachedOutboundGRPClientConn
	*ratelimit.RateLimiter
	recordingServer atomic.Pointer[recording.Server]

	// secretsResolver is long-lived (like store): created once in New, its
	// fetch loops start on Apply, and it is Closed on shutdown. It is not part
	// of authorizeState (which is rebuilt per config change).
	secretsResolver *resolver.Resolver
}

type options struct {
	policyIndexerCtor func(ssh.SSHEvaluator) ssh.PolicyIndexer
	cliController     ssh_cli.InternalCLIController
	rls               envoy_service_ratelimit_v3.RateLimitServiceServer
	secretsResolver   *resolver.Resolver
}

// Option configures the Authorize service.
type Option func(*options)

// WithPolicyIndexer sets the policy indexer constructor.
func WithPolicyIndexer(ctor func(ssh.SSHEvaluator) ssh.PolicyIndexer) Option {
	return func(o *options) {
		o.policyIndexerCtor = ctor
	}
}

func WithInternalCLIController(cliCtrl ssh_cli.InternalCLIController) Option {
	return func(o *options) {
		o.cliController = cliCtrl
	}
}

// WithRateLimitServer sets the rate limit server implementation
func WithRateLimitServer(rls envoy_service_ratelimit_v3.RateLimitServiceServer) Option {
	return func(o *options) {
		o.rls = rls
	}
}

// withSecretsResolver injects a pre-built secrets resolver (test seam for
// observing fetch behavior); production always lets New build its own.
func withSecretsResolver(r *resolver.Resolver) Option {
	return func(o *options) {
		o.secretsResolver = r
	}
}

// New validates and creates a new Authorize service from a set of config options.
func New(ctx context.Context, cfg *config.Config, opts ...Option) (*Authorize, error) {
	tracerProvider := trace.NewTracerProvider(ctx, "Authorize")
	tracer := tracerProvider.Tracer(trace.PomeriumCoreTracer)

	o := &options{
		policyIndexerCtor: func(eval ssh.SSHEvaluator) ssh.PolicyIndexer {
			return ssh.NewInMemoryPolicyIndexer(eval)
		},
		cliController: ssh.NewDefaultCLIController(cfg,
			style.NewTheme(style.Ansi16Colors,
				style.WithDeemphasizedColors(style.Ansi16Deemphasized))),
		rls: nil,
	}
	for _, opt := range opts {
		opt(o)
	}

	a := &Authorize{
		logDuration: metrics.Int64Histogram("authorize.log.duration",
			metric.WithDescription("Duration of authorize log execution."),
			metric.WithUnit("ms")),

		store:           store.New(),
		tracerProvider:  tracerProvider,
		tracer:          tracer,
		recordingServer: atomic.Pointer[recording.Server]{},
	}
	a.currentConfig.Store(cfg)

	// Create the resolver and start its fetch loops from the initial config
	// before building the evaluator state, so the evaluator never references
	// bindings the resolver has not been told about. There is no readiness
	// gating: requests that arrive before the first successful fetch fail closed.
	a.secretsResolver = o.secretsResolver
	if a.secretsResolver == nil {
		a.secretsResolver = resolver.New(secrets.DefaultRegistry())
	}
	a.applySecrets(ctx, cfg)

	state, err := newAuthorizeStateFromConfig(ctx, nil, tracerProvider, cfg, a.store, a.secretsResolver, &a.outboundGrpcConn)
	if err != nil {
		return nil, err
	}
	a.state.Store(state)
	rls := ratelimit.NewRateLimiter(trace.NewTracerProvider(ctx, "RLS"), o.rls)
	a.RateLimiter = rls
	codeIssuer := code.NewIssuer(ctx, a)
	a.accessTracker = NewAccessTracker(a, accessTrackerMaxSize, accessTrackerDebouncePeriod)
	a.policyIndexer = o.policyIndexerCtor(a)
	a.ssh = ssh.NewStreamManager(
		ctx,
		ssh.NewAuth(a, &a.currentConfig, a.tracerProvider, codeIssuer,
			ssh.WithMetricMeter(otel.Meter("ssh_auth_code")),
			ssh.WithTracer(a.tracerProvider.Tracer(trace.PomeriumCoreTracer)),
		),
		a.policyIndexer,
		o.cliController,
		cfg,
	)
	return a, nil
}

func (a *Authorize) RegisterGRPCServices(server *googlegrpc.Server, cfg *config.Config) {
	envoy_service_auth_v3.RegisterAuthorizationServer(server, a)
	extensions_ssh.RegisterStreamManagementServer(server, a)
	envoy_eds_v3.RegisterEndpointDiscoveryServiceServer(server, a.ssh)
	extensions_event_sinks_grpc.RegisterHealthCheckEventSinkServer(server, a.ssh)
	if cfg.Options.SSHRLSEnabled {
		envoy_service_ratelimit_v3.RegisterRateLimitServiceServer(server, a.RateLimiter)
	}
}

// GetDataBrokerServiceClient returns the current DataBrokerServiceClient.
func (a *Authorize) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return a.state.Load().dataBrokerClient
}

// applySecrets diffs the config's secret bindings into the resolver, starting
// or stopping fetch loops as needed. Binding validity is guaranteed by config
// validation, so a scope error here is logged, not fatal.
func (a *Authorize) applySecrets(ctx context.Context, cfg *config.Config) {
	scope, _, err := cfg.Options.Secrets.ToScope(secrets.DefaultRegistry())
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize: invalid secrets configuration")
		return
	}
	a.secretsResolver.Apply(ctx, scope)
}

// Run runs the authorize service.
func (a *Authorize) Run(ctx context.Context) error {
	// The resolver's fetch loops start in New (on Apply); stop them on shutdown.
	if a.secretsResolver != nil {
		context.AfterFunc(ctx, a.secretsResolver.Close)
	}

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
		opts.DownstreamMTLS.GetEnforcement() != configpb.MtlsEnforcementMode_POLICY

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
	// Apply the new bindings to the resolver before rebuilding the state, so the
	// evaluator snapshot new requests see never references bindings the resolver
	// has not been told about (the reverse order would open a window of spurious
	// fail-closed 503s).
	a.applySecrets(ctx, cfg)
	if newState, err := newAuthorizeStateFromConfig(ctx, currentState, a.tracerProvider, cfg, a.store, a.secretsResolver, &a.outboundGrpcConn); err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("authorize: error updating state")
	} else {
		a.state.Store(newState)
	}
	a.ssh.OnConfigChange(cfg)
}
