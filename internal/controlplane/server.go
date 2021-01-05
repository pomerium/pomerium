package controlplane

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	"github.com/gorilla/mux"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/controlplane/xdsmgr"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

type versionedOptions struct {
	config.Options
	version int64
}

type atomicVersionedOptions struct {
	value atomic.Value
}

func (avo *atomicVersionedOptions) Load() versionedOptions {
	return avo.value.Load().(versionedOptions)
}

func (avo *atomicVersionedOptions) Store(options versionedOptions) {
	avo.value.Store(options)
}

// A Server is the control-plane gRPC and HTTP servers.
type Server struct {
	GRPCListener net.Listener
	GRPCServer   *grpc.Server
	HTTPListener net.Listener
	HTTPRouter   *mux.Router

	currentConfig atomicVersionedOptions
	name          string
	xdsmgr        *xdsmgr.Manager
}

// NewServer creates a new Server. Listener ports are chosen by the OS.
func NewServer(name string) (*Server, error) {
	srv := &Server{}
	srv.currentConfig.Store(versionedOptions{})

	var err error

	// setup gRPC
	srv.GRPCListener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ui, si := grpcutil.AttachMetadataInterceptors(
		metadata.Pairs(grpcutil.MetadataKeyPomeriumVersion, version.FullVersion()),
	)
	srv.GRPCServer = grpc.NewServer(
		grpc.StatsHandler(telemetry.NewGRPCServerStatsHandler(name)),
		grpc.ChainUnaryInterceptor(requestid.UnaryServerInterceptor(), ui),
		grpc.ChainStreamInterceptor(requestid.StreamServerInterceptor(), si),
	)
	reflection.Register(srv.GRPCServer)
	srv.registerAccessLogHandlers()

	// setup HTTP
	srv.HTTPListener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = srv.GRPCListener.Close()
		return nil, err
	}
	srv.HTTPRouter = mux.NewRouter()
	srv.addHTTPMiddleware()

	srv.xdsmgr = xdsmgr.NewManager(srv.buildDiscoveryResources())
	envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(srv.GRPCServer, srv.xdsmgr)

	return srv, nil
}

// Run runs the control-plane gRPC and HTTP servers.
func (srv *Server) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)

	// start the gRPC server
	eg.Go(func() error {
		log.Info().Str("addr", srv.GRPCListener.Addr().String()).Msg("starting control-plane gRPC server")
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

	hsrv := (&http.Server{
		BaseContext: func(li net.Listener) context.Context {
			return ctx
		},
		Handler: srv.HTTPRouter,
	})

	// start the HTTP server
	eg.Go(func() error {
		log.Info().Str("addr", srv.HTTPListener.Addr().String()).Msg("starting control-plane HTTP server")
		return hsrv.Serve(srv.HTTPListener)
	})

	// gracefully stop the HTTP server on context cancellation
	eg.Go(func() error {
		<-ctx.Done()

		ctx, cleanup := context.WithTimeout(ctx, time.Second*5)
		defer cleanup()

		return hsrv.Shutdown(ctx)
	})

	return eg.Wait()
}

// OnConfigChange updates the pomerium config options.
func (srv *Server) OnConfigChange(cfg *config.Config) {
	prev := srv.currentConfig.Load()
	srv.currentConfig.Store(versionedOptions{
		Options: *cfg.Options,
		version: prev.version + 1,
	})
	srv.xdsmgr.Update(srv.buildDiscoveryResources())
}
