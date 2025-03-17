// Package pomerium houses the main pomerium CLI command.
package pomerium

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	envoy_service_auth_v3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	extensions_ssh "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh"
	extensions_session_recording "github.com/pomerium/envoy-custom/api/extensions/filters/network/ssh/filters/session_recording"

	"go.uber.org/automaxprocs/maxprocs"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/authorize"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	databroker_service "github.com/pomerium/pomerium/databroker"
	"github.com/pomerium/pomerium/internal/autocert"
	"github.com/pomerium/pomerium/internal/controlplane"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/registry"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/internal/version"
	derivecert_config "github.com/pomerium/pomerium/pkg/derivecert/config"
	"github.com/pomerium/pomerium/pkg/envoy"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	"github.com/pomerium/pomerium/proxy"
	oteltrace "go.opentelemetry.io/otel/trace"
)

type Options struct {
	fileMgr                 *filemgr.Manager
	envoyServerOptions      []envoy.ServerOption
	databrokerServerOptions []databroker_service.Option
}

type Option func(*Options)

func (o *Options) apply(opts ...Option) {
	for _, op := range opts {
		op(o)
	}
}

func WithOverrideFileManager(fileMgr *filemgr.Manager) Option {
	return func(o *Options) {
		o.fileMgr = fileMgr
	}
}

func WithEnvoyServerOptions(opts ...envoy.ServerOption) Option {
	return func(o *Options) {
		o.envoyServerOptions = append(o.envoyServerOptions, opts...)
	}
}

func WithDataBrokerServerOptions(opts ...databroker_service.Option) Option {
	return func(o *Options) {
		o.databrokerServerOptions = append(o.databrokerServerOptions, opts...)
	}
}

// Run runs the main pomerium application.
func Run(ctx context.Context, src config.Source, opts ...Option) error {
	p := New(opts...)
	tracerProvider := trace.NewTracerProvider(ctx, "Pomerium")

	if err := p.Start(ctx, tracerProvider, src); err != nil {
		return err
	}
	return p.Wait()
}

var ErrShutdown = errors.New("Shutdown() called")

type Pomerium struct {
	Options
	errGroup *errgroup.Group

	startMu     sync.Mutex
	cancel      context.CancelCauseFunc
	envoyServer *envoy.Server
}

func New(opts ...Option) *Pomerium {
	options := Options{}
	options.apply(opts...)

	return &Pomerium{
		Options: options,
	}
}

func (p *Pomerium) Start(ctx context.Context, tracerProvider oteltrace.TracerProvider, src config.Source) error {
	p.startMu.Lock()
	defer p.startMu.Unlock()
	updateTraceClient(ctx, src.GetConfig())
	ctx, p.cancel = context.WithCancelCause(ctx)
	_, _ = maxprocs.Set(maxprocs.Logger(func(s string, i ...any) { log.Ctx(ctx).Debug().Msgf(s, i...) }))

	evt := log.Ctx(ctx).Info().
		Str("envoy_version", files.FullVersion()).
		Str("version", version.FullVersion())
	if buildTime := version.BuildTime(); buildTime != "" {
		evt = evt.Str("built", buildTime)
	}
	evt.Msg("cmd/pomerium")

	src, err := config.NewLayeredSource(ctx, src, derivecert_config.NewBuilder())
	if err != nil {
		return err
	}
	src = databroker.NewConfigSource(ctx, tracerProvider, src, databroker.EnableConfigValidation(true))
	_ = config.NewLogManager(ctx, src)

	// trigger changes when underlying files are changed
	src = config.NewFileWatcherSource(ctx, src)

	src, err = autocert.New(ctx, src)
	if err != nil {
		return err
	}

	// override the default http transport so we can use the custom CA in the TLS client config (#1570)
	http.DefaultTransport = config.NewHTTPTransport(src)

	metricsMgr := config.NewMetricsManager(ctx, src)

	eventsMgr := events.New()

	fileMgr := p.fileMgr
	if fileMgr == nil {
		fileMgr = filemgr.NewManager()
	}

	cfg := src.GetConfig()
	src.OnConfigChange(ctx, updateTraceClient)

	// setup the control plane
	controlPlane, err := controlplane.NewServer(ctx, cfg, metricsMgr, eventsMgr, fileMgr)
	if err != nil {
		return fmt.Errorf("error creating control plane: %w", err)
	}
	src.OnConfigChange(ctx,
		func(ctx context.Context, cfg *config.Config) {
			if err := controlPlane.OnConfigChange(ctx, cfg); err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("config change")
			}
		})

	if err = controlPlane.OnConfigChange(ctx, src.GetConfig()); err != nil {
		return fmt.Errorf("applying config: %w", err)
	}

	log.Ctx(ctx).Info().
		Str("grpc-port", src.GetConfig().GRPCPort).
		Str("http-port", src.GetConfig().HTTPPort).
		Str("outbound-port", src.GetConfig().OutboundPort).
		Str("metrics-port", src.GetConfig().MetricsPort).
		Str("debug-port", src.GetConfig().DebugPort).
		Str("acme-tls-alpn-port", src.GetConfig().ACMETLSALPNPort).
		Msg("server started")

	// create envoy server
	p.envoyServer, err = envoy.NewServer(ctx, src, controlPlane.Builder, p.envoyServerOptions...)
	if err != nil {
		return fmt.Errorf("error creating envoy server: %w", err)
	}
	context.AfterFunc(ctx, func() {
		p.envoyServer.Close()
	})

	// add services
	if err := setupAuthenticate(ctx, src, controlPlane); err != nil {
		return err
	}
	var authorizeServer *authorize.Authorize
	if config.IsAuthorize(src.GetConfig().Options.Services) {
		authorizeServer, err = setupAuthorize(ctx, src, controlPlane)
		if err != nil {
			return err
		}
	}
	var dataBrokerServer *databroker_service.DataBroker
	if config.IsDataBroker(src.GetConfig().Options.Services) {
		dataBrokerServer, err = setupDataBroker(ctx, src, controlPlane, eventsMgr, p.databrokerServerOptions...)
		if err != nil {
			return fmt.Errorf("setting up databroker: %w", err)
		}
	}

	if err = setupRegistryReporter(ctx, tracerProvider, src); err != nil {
		return fmt.Errorf("setting up registry reporter: %w", err)
	}
	if err := setupProxy(ctx, src, controlPlane); err != nil {
		return err
	}

	// run everything
	p.errGroup, ctx = errgroup.WithContext(ctx)
	if authorizeServer != nil {
		p.errGroup.Go(func() error {
			return authorizeServer.Run(ctx)
		})
	}
	p.errGroup.Go(func() error {
		return controlPlane.Run(ctx)
	})
	if dataBrokerServer != nil {
		p.errGroup.Go(func() error {
			return dataBrokerServer.Run(ctx)
		})
	}
	return nil
}

func (p *Pomerium) Shutdown(ctx context.Context) error {
	p.startMu.Lock()
	envoyServer := p.envoyServer
	p.startMu.Unlock()
	var errs []error
	if envoyServer != nil {
		_ = trace.WaitForSpans(ctx, p.envoyServer.ExitGracePeriod())
		errs = append(errs, p.envoyServer.Close()) // this only errors if signaling envoy fails
	}
	p.cancel(ErrShutdown)
	errs = append(errs, p.Wait())
	return errors.Join(errs...)
}

func (p *Pomerium) Wait() error {
	err := p.errGroup.Wait()
	if errors.Is(err, ErrShutdown) {
		return nil
	}
	return err
}

func setupAuthenticate(ctx context.Context, src config.Source, controlPlane *controlplane.Server) error {
	if !config.IsAuthenticate(src.GetConfig().Options.Services) {
		return nil
	}

	svc, err := authenticate.New(ctx, src.GetConfig())
	if err != nil {
		return fmt.Errorf("error creating authenticate service: %w", err)
	}
	err = controlPlane.EnableAuthenticate(ctx, svc)
	if err != nil {
		return fmt.Errorf("error adding authenticate service to control plane: %w", err)
	}

	src.OnConfigChange(ctx, svc.OnConfigChange)
	svc.OnConfigChange(ctx, src.GetConfig())
	log.Ctx(ctx).Info().Msg("enabled authenticate service")

	return nil
}

func setupAuthorize(ctx context.Context, src config.Source, controlPlane *controlplane.Server) (*authorize.Authorize, error) {
	svc, err := authorize.New(ctx, src.GetConfig())
	if err != nil {
		return nil, fmt.Errorf("error creating authorize service: %w", err)
	}
	envoy_service_auth_v3.RegisterAuthorizationServer(controlPlane.GRPCServer, svc)
	extensions_ssh.RegisterStreamManagementServer(controlPlane.GRPCServer, svc)
	extensions_session_recording.RegisterRecordingServiceServer(controlPlane.GRPCServer, svc)

	log.Ctx(ctx).Info().Msg("enabled authorize service")
	src.OnConfigChange(ctx, svc.OnConfigChange)
	svc.OnConfigChange(ctx, src.GetConfig())
	return svc, nil
}

func setupDataBroker(ctx context.Context,
	src config.Source,
	controlPlane *controlplane.Server,
	eventsMgr *events.Manager,
	opts ...databroker_service.Option,
) (*databroker_service.DataBroker, error) {
	svc, err := databroker_service.New(ctx, src.GetConfig(), eventsMgr, opts...)
	if err != nil {
		return nil, fmt.Errorf("error creating databroker service: %w", err)
	}
	svc.Register(controlPlane.GRPCServer)
	log.Ctx(ctx).Info().Msg("enabled databroker service")
	src.OnConfigChange(ctx, svc.OnConfigChange)
	svc.OnConfigChange(ctx, src.GetConfig())
	return svc, nil
}

func setupRegistryReporter(ctx context.Context, tracerProvider oteltrace.TracerProvider, src config.Source) error {
	reporter := registry.NewReporter(tracerProvider)
	src.OnConfigChange(ctx, reporter.OnConfigChange)
	reporter.OnConfigChange(ctx, src.GetConfig())
	return nil
}

func setupProxy(ctx context.Context, src config.Source, controlPlane *controlplane.Server) error {
	if !config.IsProxy(src.GetConfig().Options.Services) {
		return nil
	}

	svc, err := proxy.New(ctx, src.GetConfig())
	if err != nil {
		return fmt.Errorf("error creating proxy service: %w", err)
	}
	err = controlPlane.EnableProxy(ctx, svc)
	if err != nil {
		return fmt.Errorf("error adding proxy service to control plane: %w", err)
	}

	log.Ctx(ctx).Info().Msg("enabled proxy service")
	src.OnConfigChange(ctx, svc.OnConfigChange)
	svc.OnConfigChange(ctx, src.GetConfig())

	return nil
}

func updateTraceClient(ctx context.Context, cfg *config.Config) {
	sc, ok := trace.RemoteClientFromContext(ctx).(trace.SyncClient)
	if !ok {
		return
	}
	newClient, err := trace.NewTraceClientFromConfig(cfg.Options.Tracing)
	if err != nil {
		log.Ctx(ctx).Warn().Err(err).Msg("error configuring trace client")
	} else {
		go func() {
			if err := sc.Update(ctx, newClient); err != nil {
				log.Ctx(ctx).
					Warn().
					Err(err).
					Msg("error updating trace client")
			}
			provider := "none"
			if cfg.Options.Tracing.OtelTracesExporter != nil {
				provider = *cfg.Options.Tracing.OtelTracesExporter
			}
			log.Ctx(ctx).
				Debug().
				Str("provider", provider).
				Msg("trace client updated")
		}()
	}
}
