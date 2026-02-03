package controlplane

import (
	"context"
	"net"
	"net/http"
	"net/url"
	stdslices "slices"
	"sync/atomic"
	"time"

	"connectrpc.com/grpchealth"
	"connectrpc.com/grpcreflect"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/gorilla/mux"
	"github.com/libp2p/go-reuseport"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel"
	oteltrace "go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"golang.org/x/net/nettest"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/admin"
	"google.golang.org/grpc/channelz/grpc_channelz_v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/controlplane/xdsmgr"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/httputil/reproxy"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/mcp/extproc"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	pom_grpc "github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/config/configconnect"
	healthpb "github.com/pomerium/pomerium/pkg/grpc/health"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/httputil"
	"github.com/pomerium/pomerium/pkg/slices"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

type Options struct {
	startTime       time.Time
	extProcCallback extproc.Callback
}

func (o *Options) Apply(opts ...Option) {
	o.startTime = time.Now()
	for _, opt := range opts {
		opt(o)
	}
}

type Option func(o *Options)

func WithStartTime(t time.Time) Option {
	return func(o *Options) {
		o.startTime = t
	}
}

// WithExtProcCallback sets a callback that is invoked when ext_proc processes response headers.
// This is primarily used for testing to verify ext_proc is being invoked.
func WithExtProcCallback(cb extproc.Callback) Option {
	return func(o *Options) {
		o.extProcCallback = cb
	}
}

// A Service can be mounted on the control plane.
type Service interface {
	Mount(r *mux.Router)
}

// A Server is the control-plane gRPC and HTTP servers.
type Server struct {
	coltracepb.UnimplementedTraceServiceServer
	ConnectListener     net.Listener
	ConnectMux          *http.ServeMux
	GRPCListener        net.Listener
	GRPCServer          *grpc.Server
	HTTPListener        net.Listener
	MetricsListener     net.Listener
	MetricsRouter       *mux.Router
	DebugListener       net.Listener
	HealthCheckRouter   *mux.Router
	HealthCheckListener net.Listener
	healthMetrics       *health.Metrics
	ProbeProvider       atomic.Pointer[health.HTTPProvider]
	SystemdProvider     atomic.Pointer[health.SystemdProvider]
	GrpcStreamProvider  atomic.Pointer[health.GRPCStreamProvider]
	Builder             *envoyconfig.Builder
	EventsMgr           *events.Manager

	updateConfig  chan *config.Config
	currentConfig atomic.Pointer[config.Config]
	name          string
	xdsmgr        *xdsmgr.Manager
	filemgr       *filemgr.Manager
	metricsMgr    *config.MetricsManager
	reproxy       *reproxy.Handler

	httpRouter      atomic.Pointer[mux.Router]
	authenticateSvc Service
	proxySvc        Service
	debug           *debugServer

	haveSetCapacity map[string]bool

	tracerProvider oteltrace.TracerProvider
	tracer         oteltrace.Tracer

	outboundGRPCConnection pom_grpc.CachedOutboundGRPClientConn
	channelZClient         atomic.Pointer[grpc_channelz_v1.ChannelzClient]
	channelZCleanup        func()

	options *Options
}

// NewServer creates a new Server. Listener ports are chosen by the OS.
func NewServer(
	ctx context.Context,
	cfg *config.Config,
	metricsMgr *config.MetricsManager,
	eventsMgr *events.Manager,
	fileMgr *filemgr.Manager,
	opts ...Option,
) (*Server, error) {
	options := &Options{}
	options.Apply(opts...)
	tracerProvider := trace.NewTracerProvider(ctx, "Control Plane")
	var err error
	metrics, err := health.NewMetrics(otel.Meter("health"))
	if err != nil {
		return nil, err
	}
	srv := &Server{
		tracerProvider:  tracerProvider,
		tracer:          tracerProvider.Tracer(trace.PomeriumCoreTracer),
		metricsMgr:      metricsMgr,
		EventsMgr:       eventsMgr,
		filemgr:         fileMgr,
		reproxy:         reproxy.New(),
		haveSetCapacity: map[string]bool{},
		updateConfig:    make(chan *config.Config, 1),
		healthMetrics:   metrics,
		options:         options,
	}
	srv.currentConfig.Store(cfg)
	srv.httpRouter.Store(mux.NewRouter())

	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("server-name", cfg.Options.Services)
	})

	// setup connect
	srv.ConnectListener, err = reuseport.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.ConnectPort))
	if err != nil {
		return nil, err
	}
	// support gRPC health and the reflection service
	srv.ConnectMux = http.NewServeMux()
	checker := grpchealth.NewStaticChecker(configconnect.ConfigServiceName)
	srv.ConnectMux.Handle(grpchealth.NewHandler(checker))
	reflector := grpcreflect.NewStaticReflector(
		grpchealth.HealthV1ServiceName,
		configconnect.ConfigServiceName,
	)
	srv.ConnectMux.Handle(grpcreflect.NewHandlerV1(reflector))
	srv.ConnectMux.Handle(grpcreflect.NewHandlerV1Alpha(reflector))

	// setup gRPC
	srv.GRPCListener, err = reuseport.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.GRPCPort))
	if err != nil {
		_ = srv.ConnectListener.Close()
		return nil, err
	}
	ui, si := grpcutil.AttachMetadataInterceptors(
		metadata.Pairs(
			grpcutil.MetadataKeyEnvoyVersion, files.FullVersion(),
			grpcutil.MetadataKeyPomeriumVersion, version.FullVersion(),
		),
	)
	srv.GRPCServer = grpc.NewServer(
		grpc.StatsHandler(otelgrpc.NewServerHandler(otelgrpc.WithTracerProvider(tracerProvider))),
		grpc.ChainUnaryInterceptor(
			log.UnaryServerInterceptor(log.Ctx(ctx)),
			requestid.UnaryServerInterceptor(),
			ui,
		),
		grpc.ChainStreamInterceptor(
			log.StreamServerInterceptor(log.Ctx(ctx)),
			requestid.StreamServerInterceptor(),
			si,
		),
	)
	if cfg.Options.IsRuntimeFlagSet(config.RuntimeFlagDebugAdminEndpoints) {
		cleanup, _ := admin.Register(srv.GRPCServer)
		srv.channelZCleanup = cleanup
	}
	reflection.Register(srv.GRPCServer)
	srv.registerAccessLogHandlers()

	grpc_health_v1.RegisterHealthServer(srv.GRPCServer, pom_grpc.NewHealthCheckServer())
	healthpb.RegisterHealthNotifierServer(srv.GRPCServer, srv)

	// Register ext_proc server for MCP response interception
	extProcServer := extproc.NewServer(options.extProcCallback)
	extProcServer.Register(srv.GRPCServer)

	// setup HTTP
	srv.HTTPListener, err = reuseport.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.HTTPPort))
	if err != nil {
		_ = srv.ConnectListener.Close()
		_ = srv.GRPCListener.Close()
		return nil, err
	}

	srv.MetricsListener, err = reuseport.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.MetricsPort))
	if err != nil {
		_ = srv.ConnectListener.Close()
		_ = srv.GRPCListener.Close()
		_ = srv.HTTPListener.Close()
		return nil, err
	}

	srv.DebugListener, err = reuseport.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.DebugPort))
	if err != nil {
		_ = srv.ConnectListener.Close()
		_ = srv.GRPCListener.Close()
		_ = srv.HTTPListener.Close()
		_ = srv.MetricsListener.Close()
		return nil, err
	}

	srv.HealthCheckListener, err = reuseport.Listen("tcp4", cfg.Options.HealthCheckAddr)
	if err != nil {
		return nil, err
	}
	srv.updateHealthProviders(ctx, cfg)
	if err := srv.updateRouter(ctx, cfg); err != nil {
		return nil, err
	}
	srv.debug = newDebugServer(cfg, srv)
	srv.MetricsRouter = mux.NewRouter()
	srv.HealthCheckRouter = mux.NewRouter()

	// metrics
	srv.MetricsRouter.Handle(endpoints.PathMetrics, srv.metricsMgr)

	// health
	srv.HealthCheckRouter.Path(endpoints.PathStatus).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := srv.ProbeProvider.Load()
		if p != nil {
			http.HandlerFunc(p.Status).ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	srv.HealthCheckRouter.Path(endpoints.PathStartupz).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := srv.ProbeProvider.Load()
		if p != nil {
			http.HandlerFunc(p.StartupProbe).ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	srv.HealthCheckRouter.Path(endpoints.PathHealthz).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := srv.ProbeProvider.Load()
		if p != nil {
			http.HandlerFunc(p.LivenessProbe).ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	srv.HealthCheckRouter.Path(endpoints.PathReadyz).HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := srv.ProbeProvider.Load()
		if p != nil {
			http.HandlerFunc(p.ReadyProbe).ServeHTTP(w, r)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})

	srv.filemgr.ClearCache()

	srv.Builder = envoyconfig.New(
		srv.ConnectListener.Addr().String(),
		srv.GRPCListener.Addr().String(),
		srv.HTTPListener.Addr().String(),
		srv.DebugListener.Addr().String(),
		srv.MetricsListener.Addr().String(),
		srv.filemgr,
		srv.reproxy,
		nettest.SupportsIPv6(),
	)

	res, err := srv.buildDiscoveryResources(ctx)
	if err != nil {
		return nil, err
	}

	srv.xdsmgr = xdsmgr.NewManager(res)
	envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(srv.GRPCServer, srv.xdsmgr)
	if exp := trace.ExporterServerFromContext(ctx); exp != nil {
		coltracepb.RegisterTraceServiceServer(srv.GRPCServer, exp)
	}
	return srv, nil
}

// Run runs the control-plane gRPC and HTTP servers.
func (srv *Server) Run(ctx context.Context) error {
	defer func() {
		if srv.channelZCleanup != nil {
			srv.channelZCleanup()
		}
	}()
	eg, ctx := errgroup.WithContext(ctx)

	handle := srv.EventsMgr.Register(func(evt events.Event) {
		withGRPCBackoff(ctx, func() error {
			return srv.storeEvent(ctx, evt)
		})
	})
	defer srv.EventsMgr.Unregister(handle)

	// start the gRPC server
	eg.Go(func() error {
		log.Ctx(ctx).Debug().Str("addr", srv.GRPCListener.Addr().String()).Msg("starting control-plane gRPC server")
		return grpcutil.ServeWithGracefulStop(ctx, srv.GRPCServer, srv.GRPCListener, time.Second*5)
	})

	for _, entry := range []struct {
		Name     string
		Listener net.Listener
		Handler  http.Handler
	}{
		{"connect", srv.ConnectListener, srv.ConnectMux},
		{"http", srv.HTTPListener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srv.httpRouter.Load().ServeHTTP(w, r)
		})},
		{"debug", srv.DebugListener, srv.debug},
		{"metrics", srv.MetricsListener, srv.MetricsRouter},
		{"health", srv.HealthCheckListener, srv.HealthCheckRouter},
	} {
		// start the HTTP server
		eg.Go(func() error {
			log.Ctx(ctx).Debug().
				Str("addr", entry.Listener.Addr().String()).
				Msgf("starting control-plane %s server", entry.Name)
			return httputil.ServeWithGracefulStop(ctx, entry.Handler, entry.Listener, time.Second*5)
		})
	}

	// apply configuration changes
	eg.Go(func() error {
		for {
			select {
			case <-ctx.Done():
				return context.Cause(ctx)
			case cfg := <-srv.updateConfig:
				err := srv.update(ctx, cfg)
				if err != nil {
					log.Ctx(ctx).Error().Err(err).
						Msg("controlplane: error updating server with new config")
				}
			}
		}
	})

	return eg.Wait()
}

// OnConfigChange updates the pomerium config options.
func (srv *Server) OnConfigChange(ctx context.Context, cfg *config.Config) error {
	ctx, span := srv.tracer.Start(ctx, "controlplane.Server.OnConfigChange")
	defer span.End()

	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case srv.updateConfig <- cfg:
	}
	return nil
}

// EnableAuthenticate enables the authenticate service.
func (srv *Server) EnableAuthenticate(ctx context.Context, svc Service) error {
	srv.authenticateSvc = svc
	return srv.updateRouter(ctx, srv.currentConfig.Load())
}

// EnableProxy enables the proxy service.
func (srv *Server) EnableProxy(ctx context.Context, svc Service) error {
	srv.proxySvc = svc
	return srv.updateRouter(ctx, srv.currentConfig.Load())
}

// EnableDataBrokerDebug enables the databroker browser.
func (srv *Server) EnableDataBrokerDebug(client DataBrokerClientProvider) {
	srv.debug.SetDataBrokerClient(client)
}

func (srv *Server) GetChannelZClient() (grpc_channelz_v1.ChannelzClient, error) {
	client := srv.channelZClient.Load()
	if client != nil {
		return *client, nil
	}
	dialOpts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}
	cc, err := grpc.NewClient(srv.GRPCListener.Addr().String(), dialOpts...)
	if err != nil {
		return nil, err
	}
	cl := grpc_channelz_v1.NewChannelzClient(cc)
	srv.channelZClient.Store(&cl)
	return cl, nil
}

func (srv *Server) update(ctx context.Context, cfg *config.Config) error {
	ctx, span := srv.tracer.Start(ctx, "controlplane.Server.update")
	defer span.End()

	if err := srv.updateRouter(ctx, cfg); err != nil {
		return err
	}
	srv.reproxy.Update(ctx, cfg)
	srv.currentConfig.Store(cfg)
	srv.debug.Update(cfg)

	res, err := srv.buildDiscoveryResources(ctx)
	if err != nil {
		return err
	}
	srv.xdsmgr.Update(ctx, res)
	return nil
}

func (srv *Server) updateRouter(ctx context.Context, cfg *config.Config) error {
	httpRouter := mux.NewRouter()
	srv.addHTTPMiddleware(ctx, httpRouter, cfg)
	if err := srv.mountCommonEndpoints(httpRouter, cfg); err != nil {
		return err
	}
	if srv.authenticateSvc != nil {
		seen := make(map[string]struct{})
		// mount auth handler for both internal and external endpoints
		for _, fn := range []func() (*url.URL, error){cfg.Options.GetAuthenticateURL, cfg.Options.GetInternalAuthenticateURL} {
			authenticateURL, err := fn()
			if err != nil {
				return err
			}
			authenticateHost := urlutil.StripPort(authenticateURL.Host)
			if _, ok := seen[authenticateHost]; ok {
				continue
			}
			seen[authenticateHost] = struct{}{}
			srv.authenticateSvc.Mount(httpRouter.Host(authenticateHost).Subrouter())
		}
	}
	if srv.proxySvc != nil {
		srv.proxySvc.Mount(httpRouter)
	}
	srv.httpRouter.Store(httpRouter)
	return nil
}

func (srv *Server) updateHealthProviders(ctx context.Context, cfg *config.Config) {
	checks := srv.getExpectedHealthChecks(cfg)
	checks = slices.Unique(append(checks, health.FromContextHealthChecks(ctx)...))
	mgr := health.GetProviderManager()
	httpProvider := health.NewHTTPProvider(mgr, health.WithExpectedChecks(
		checks...,
	))

	metricsProvider := health.NewMetricsProvider(
		ctx,
		srv.healthMetrics,
		mgr,
		srv.options.startTime,
	)

	sharedKey, err := cfg.Options.GetSharedKey()
	if err == nil {
		srv.updateHealthStreamProvider(ctx, mgr, sharedKey, checks)
	} else {
		log.Ctx(ctx).Error().Err(err).Msg("health stream: failed to load shared key, will not update")
	}
	srv.ProbeProvider.Store(httpProvider)
	mgr.Register(health.ProviderHTTP, httpProvider)
	mgr.Register(health.ProviderMetrics, metricsProvider)
	srv.configureExtraProviders(ctx, cfg, mgr, checks)
}

func (srv *Server) updateHealthStreamProvider(ctx context.Context, mgr health.ProviderManager, sharedKey []byte, checks []health.Check) {
	if prevProvider := srv.GrpcStreamProvider.Load(); prevProvider != nil {
		prevProvider.Close()
	}
	grpcStreamProvider := health.NewGRPCStreamProvider(
		ctx,
		mgr,
		time.Second*15,
		stdslices.Clone(sharedKey),
		health.WithExpectedChecks(
			checks...,
		),
	)
	mgr.Register(health.ProviderGRPCStream, grpcStreamProvider)
	srv.GrpcStreamProvider.Store(grpcStreamProvider)
}

func (srv *Server) getExpectedHealthChecks(cfg *config.Config) (ret []health.Check) {
	services := cfg.Options.Services
	if config.IsAuthenticate(services) {
		ret = append(ret, health.AuthenticateService)
	}
	if config.IsAuthorize(services) {
		ret = append(ret, health.AuthorizationService)
	}
	if config.IsDataBroker(services) {
		ret = append(
			ret,
			health.StorageBackend,
			health.DatabrokerInitialSync,
			health.DatabrokerBuildConfig,
			health.DatabrokerCluster,
		)
		if cfg.Options.DataBroker.StorageType == config.StoragePostgresName {
			ret = append(
				ret,
				health.StorageBackendCleanup,
			)
		}
	}
	if config.IsProxy(services) {
		ret = append(
			ret, health.ProxyService,
			health.XDSRouteConfiguration,
		)
	}

	ret = append(
		ret,
		// contingent on control plane
		health.XDSCluster,
		health.XDSListener,
		health.EnvoyServer,
	)
	return ret
}

var _ healthpb.HealthNotifierServer = (*Server)(nil)

func (srv *Server) SyncHealth(in *healthpb.HealthStreamRequest, remote grpc.ServerStreamingServer[healthpb.HealthMessage]) error {
	p := srv.GrpcStreamProvider.Load()
	if p == nil {
		return status.Error(codes.Unavailable, "health streaming server not yet available")
	}
	return p.SyncHealth(in, remote)
}
