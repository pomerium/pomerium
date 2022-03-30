package controlplane

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
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
	"github.com/pomerium/pomerium/internal/controlplane/xdsmgr"
	"github.com/pomerium/pomerium/internal/envoy/files"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/httputil/reproxy"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/version"
	pom_grpc "github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type versionedConfig struct {
	*config.Config
	version int64
}

type atomicVersionedConfig struct {
	value atomic.Value
}

func (avo *atomicVersionedConfig) Load() versionedConfig {
	return avo.value.Load().(versionedConfig)
}

func (avo *atomicVersionedConfig) Store(cfg versionedConfig) {
	avo.value.Store(cfg)
}

// A Server is the control-plane gRPC and HTTP servers.
type Server struct {
	GRPCListener    net.Listener
	GRPCServer      *grpc.Server
	HTTPListener    net.Listener
	HTTPRouter      *mux.Router
	MetricsListener net.Listener
	MetricsRouter   *mux.Router
	DebugListener   net.Listener
	DebugRouter     *mux.Router
	Builder         *envoyconfig.Builder

	currentConfig atomicVersionedConfig
	name          string
	xdsmgr        *xdsmgr.Manager
	filemgr       *filemgr.Manager
	metricsMgr    *config.MetricsManager
	reproxy       *reproxy.Handler

	haveSetCapacity map[string]bool
}

// NewServer creates a new Server. Listener ports are chosen by the OS.
func NewServer(cfg *config.Config, metricsMgr *config.MetricsManager) (*Server, error) {
	srv := &Server{
		metricsMgr:      metricsMgr,
		reproxy:         reproxy.New(),
		haveSetCapacity: map[string]bool{},
	}
	srv.currentConfig.Store(versionedConfig{
		Config: cfg,
	})

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

	srv.HTTPRouter = mux.NewRouter()
	srv.DebugRouter = mux.NewRouter()
	srv.MetricsRouter = mux.NewRouter()
	srv.addHTTPMiddleware()

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

	srv.xdsmgr = xdsmgr.NewManager(res)
	envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(srv.GRPCServer, srv.xdsmgr)

	return srv, nil
}

// Run runs the control-plane gRPC and HTTP servers.
func (srv *Server) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	handle := events.Register(func(evt events.Event) {
		withGRPCBackoff(ctx, func() error {
			return srv.storeEvent(ctx, evt)
		})
	})
	defer events.Unregister(handle)

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
		Handler  *mux.Router
	}{
		{"http", srv.HTTPListener, srv.HTTPRouter},
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
