package controlplane

import (
	"context"
	"net"
	"net/http"
	"net/http/pprof"
	"net/url"
	"time"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/gorilla/mux"
	"github.com/libp2p/go-reuseport"
	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	oteltrace "go.opentelemetry.io/otel/trace"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"golang.org/x/net/nettest"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/config/envoyconfig"
	"github.com/pomerium/pomerium/config/envoyconfig/filemgr"
	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/internal/controlplane/xdsmgr"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/httputil/reproxy"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	pom_grpc "github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/httputil"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

// A Service can be mounted on the control plane.
type Service interface {
	Mount(r *mux.Router)
}

// A Server is the control-plane gRPC and HTTP servers.
type Server struct {
	coltracepb.UnimplementedTraceServiceServer
	GRPCListener    net.Listener
	GRPCServer      *grpc.Server
	HTTPListener    net.Listener
	MetricsListener net.Listener
	MetricsRouter   *mux.Router
	DebugListener   net.Listener
	DebugRouter     *mux.Router
	Builder         *envoyconfig.Builder
	EventsMgr       *events.Manager

	updateConfig  chan *config.Config
	currentConfig *atomicutil.Value[*config.Config]
	name          string
	xdsmgr        *xdsmgr.Manager
	filemgr       *filemgr.Manager
	metricsMgr    *config.MetricsManager
	reproxy       *reproxy.Handler

	httpRouter      *atomicutil.Value[*mux.Router]
	authenticateSvc Service
	proxySvc        Service

	haveSetCapacity map[string]bool

	tracerProvider oteltrace.TracerProvider
	tracer         oteltrace.Tracer
}

// NewServer creates a new Server. Listener ports are chosen by the OS.
func NewServer(
	ctx context.Context,
	cfg *config.Config,
	metricsMgr *config.MetricsManager,
	eventsMgr *events.Manager,
	fileMgr *filemgr.Manager,
) (*Server, error) {
	tracerProvider := trace.NewTracerProvider(ctx, "Control Plane")
	srv := &Server{
		tracerProvider:  tracerProvider,
		tracer:          tracerProvider.Tracer(trace.PomeriumCoreTracer),
		metricsMgr:      metricsMgr,
		EventsMgr:       eventsMgr,
		filemgr:         fileMgr,
		reproxy:         reproxy.New(),
		haveSetCapacity: map[string]bool{},
		updateConfig:    make(chan *config.Config, 1),
		currentConfig:   atomicutil.NewValue(cfg),
		httpRouter:      atomicutil.NewValue(mux.NewRouter()),
	}

	ctx = log.WithContext(ctx, func(c zerolog.Context) zerolog.Context {
		return c.Str("server-name", cfg.Options.Services)
	})

	var err error

	// setup gRPC
	srv.GRPCListener, err = reuseport.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.GRPCPort))
	if err != nil {
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
	reflection.Register(srv.GRPCServer)
	srv.registerAccessLogHandlers()

	grpc_health_v1.RegisterHealthServer(srv.GRPCServer, pom_grpc.NewHealthCheckServer())

	// setup HTTP
	srv.HTTPListener, err = reuseport.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.HTTPPort))
	if err != nil {
		_ = srv.GRPCListener.Close()
		return nil, err
	}

	srv.MetricsListener, err = reuseport.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.MetricsPort))
	if err != nil {
		_ = srv.GRPCListener.Close()
		_ = srv.HTTPListener.Close()
		return nil, err
	}

	srv.DebugListener, err = reuseport.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.DebugPort))
	if err != nil {
		_ = srv.GRPCListener.Close()
		_ = srv.HTTPListener.Close()
		_ = srv.MetricsListener.Close()
		return nil, err
	}

	if err := srv.updateRouter(ctx, cfg); err != nil {
		return nil, err
	}
	srv.DebugRouter = mux.NewRouter()
	srv.MetricsRouter = mux.NewRouter()

	// pprof
	srv.DebugRouter.Path("/debug/pprof/cmdline").HandlerFunc(pprof.Cmdline)
	srv.DebugRouter.Path("/debug/pprof/profile").HandlerFunc(pprof.Profile)
	srv.DebugRouter.Path("/debug/pprof/symbol").HandlerFunc(pprof.Symbol)
	srv.DebugRouter.Path("/debug/pprof/trace").HandlerFunc(pprof.Trace)
	srv.DebugRouter.PathPrefix("/debug/pprof/").HandlerFunc(pprof.Index)

	// metrics
	srv.MetricsRouter.Handle("/metrics", srv.metricsMgr)

	srv.filemgr.ClearCache()

	srv.Builder = envoyconfig.New(
		srv.GRPCListener.Addr().String(),
		srv.HTTPListener.Addr().String(),
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
		{"http", srv.HTTPListener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srv.httpRouter.Load().ServeHTTP(w, r)
		})},
		{"debug", srv.DebugListener, srv.DebugRouter},
		{"metrics", srv.MetricsListener, srv.MetricsRouter},
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

func (srv *Server) update(ctx context.Context, cfg *config.Config) error {
	ctx, span := srv.tracer.Start(ctx, "controlplane.Server.update")
	defer span.End()

	if err := srv.updateRouter(ctx, cfg); err != nil {
		return err
	}
	srv.reproxy.Update(ctx, cfg)
	srv.currentConfig.Store(cfg)
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
