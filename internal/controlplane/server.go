package controlplane

import (
	"context"
	"net"
	"net/http"
	"net/http/pprof"
	"time"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
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
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/envoy/files"
	pom_grpc "github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type versionedConfig struct {
	*config.Config
	version int64
}

// A Service can be mounted on the control plane.
type Service interface {
	Mount(r *mux.Router)
}

// A Server is the control-plane gRPC and HTTP servers.
type Server struct {
	GRPCListener    net.Listener
	GRPCServer      *grpc.Server
	HTTPListener    net.Listener
	MetricsListener net.Listener
	MetricsRouter   *mux.Router
	DebugListener   net.Listener
	DebugRouter     *mux.Router
	Builder         *envoyconfig.Builder
	EventsMgr       *events.Manager

	currentConfig *atomicutil.Value[versionedConfig]
	name          string
	xdsmgr        *xdsmgr.Manager
	filemgr       *filemgr.Manager
	metricsMgr    *config.MetricsManager
	reproxy       *reproxy.Handler

	httpRouter      *atomicutil.Value[*mux.Router]
	authenticateSvc Service
	proxySvc        Service

	haveSetCapacity map[string]bool
}

// NewServer creates a new Server. Listener ports are chosen by the OS.
func NewServer(cfg *config.Config, metricsMgr *config.MetricsManager, eventsMgr *events.Manager) (*Server, error) {
	srv := &Server{
		metricsMgr:      metricsMgr,
		EventsMgr:       eventsMgr,
		reproxy:         reproxy.New(),
		haveSetCapacity: map[string]bool{},
		currentConfig: atomicutil.NewValue(versionedConfig{
			Config: cfg,
		}),
		httpRouter: atomicutil.NewValue(mux.NewRouter()),
	}

	var err error

	// setup gRPC
	srv.GRPCListener, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.GRPCPort))
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
		grpc.StatsHandler(telemetry.NewGRPCServerStatsHandler(cfg.Options.Services)),
		grpc.ChainUnaryInterceptor(requestid.UnaryServerInterceptor(), ui),
		grpc.ChainStreamInterceptor(requestid.StreamServerInterceptor(), si),
	)
	reflection.Register(srv.GRPCServer)
	srv.registerAccessLogHandlers()

	grpc_health_v1.RegisterHealthServer(srv.GRPCServer, pom_grpc.NewHealthCheckServer())

	// setup HTTP
	srv.HTTPListener, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.HTTPPort))
	if err != nil {
		_ = srv.GRPCListener.Close()
		return nil, err
	}

	srv.MetricsListener, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.MetricsPort))
	if err != nil {
		_ = srv.GRPCListener.Close()
		_ = srv.HTTPListener.Close()
		return nil, err
	}

	srv.DebugListener, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.1", cfg.DebugPort))
	if err != nil {
		_ = srv.GRPCListener.Close()
		_ = srv.HTTPListener.Close()
		_ = srv.DebugListener.Close()
		return nil, err
	}

	if err := srv.updateRouter(cfg); err != nil {
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

	srv.filemgr = filemgr.NewManager()
	srv.filemgr.ClearCache()

	srv.Builder = envoyconfig.New(
		srv.GRPCListener.Addr().String(),
		srv.HTTPListener.Addr().String(),
		srv.MetricsListener.Addr().String(),
		srv.filemgr,
		srv.reproxy,
	)

	ctx := log.WithContext(context.Background(), func(c zerolog.Context) zerolog.Context {
		return c.Str("server_name", cfg.Options.Services)
	})

	res, err := srv.buildDiscoveryResources(ctx)
	if err != nil {
		return nil, err
	}

	srv.xdsmgr = xdsmgr.NewManager(res, eventsMgr)
	envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(srv.GRPCServer, srv.xdsmgr)

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
		log.Info(ctx).Str("addr", srv.GRPCListener.Addr().String()).Msg("starting control-plane gRPC server")
		return srv.GRPCServer.Serve(srv.GRPCListener)
	})

	// gracefully stop the gRPC server on context cancellation
	eg.Go(func() error {
		<-ctx.Done()

		ctx, cancel := context.WithCancel(ctx)
		ctx, cleanup := context.WithTimeout(ctx, time.Second*5)
		defer cleanup()

		go func() {
			srv.GRPCServer.GracefulStop()
			cancel()
		}()

		go func() {
			<-ctx.Done()
			srv.GRPCServer.Stop()
			cancel()
		}()

		<-ctx.Done()

		return nil
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
		entry := entry
		hsrv := (&http.Server{
			BaseContext: func(li net.Listener) context.Context {
				return ctx
			},
			Handler: entry.Handler,
		})

		// start the HTTP server
		eg.Go(func() error {
			log.Info(ctx).
				Str("addr", entry.Listener.Addr().String()).
				Msgf("starting control-plane %s server", entry.Name)
			return hsrv.Serve(entry.Listener)
		})

		// gracefully stop the HTTP server on context cancellation
		eg.Go(func() error {
			<-ctx.Done()

			ctx, cleanup := context.WithTimeout(ctx, time.Second*5)
			defer cleanup()

			return hsrv.Shutdown(ctx)
		})
	}

	return eg.Wait()
}

// OnConfigChange updates the pomerium config options.
func (srv *Server) OnConfigChange(ctx context.Context, cfg *config.Config) error {
	if err := srv.updateRouter(cfg); err != nil {
		return err
	}
	srv.reproxy.Update(ctx, cfg)
	prev := srv.currentConfig.Load()
	srv.currentConfig.Store(versionedConfig{
		Config:  cfg,
		version: prev.version + 1,
	})
	res, err := srv.buildDiscoveryResources(ctx)
	if err != nil {
		return err
	}
	srv.xdsmgr.Update(ctx, res)
	return nil
}

// EnableAuthenticate enables the authenticate service.
func (srv *Server) EnableAuthenticate(svc Service) error {
	srv.authenticateSvc = svc
	return srv.updateRouter(srv.currentConfig.Load().Config)
}

// EnableProxy enables the proxy service.
func (srv *Server) EnableProxy(svc Service) error {
	srv.proxySvc = svc
	return srv.updateRouter(srv.currentConfig.Load().Config)
}

func (srv *Server) updateRouter(cfg *config.Config) error {
	httpRouter := mux.NewRouter()
	srv.addHTTPMiddleware(httpRouter, cfg)
	if srv.authenticateSvc != nil {
		authenticateURL, err := cfg.Options.GetInternalAuthenticateURL()
		if err != nil {
			return err
		}
		authenticateHost := urlutil.StripPort(authenticateURL.Host)
		srv.authenticateSvc.Mount(httpRouter.Host(authenticateHost).Subrouter())
	}
	if srv.proxySvc != nil {
		srv.proxySvc.Mount(httpRouter)
	}
	srv.httpRouter.Store(httpRouter)
	return nil
}
