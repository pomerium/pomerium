package controlplane

import (
	"context"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/gorilla/mux"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
)

type versionedOptions struct {
	config.Options
	version int64
}

// A Server is the control-plane gRPC and HTTP servers.
type Server struct {
	GRPCListener net.Listener
	GRPCServer   *grpc.Server
	HTTPListener net.Listener
	HTTPRouter   *mux.Router

	currentConfig atomic.Value
	configUpdated chan struct{}
}

// NewServer creates a new Server. Listener ports are chosen by the OS.
func NewServer() (*Server, error) {
	srv := &Server{
		configUpdated: make(chan struct{}, 1),
	}
	srv.currentConfig.Store(versionedOptions{})

	var err error

	// setup gRPC
	srv.GRPCListener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	srv.GRPCServer = grpc.NewServer()
	srv.registerXDSHandlers()
	srv.registerAccessLogHandlers()

	// setup HTTP
	srv.HTTPListener, err = net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = srv.GRPCListener.Close()
		return nil, err
	}
	srv.HTTPRouter = mux.NewRouter()
	srv.addHTTPMiddleware()

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

// UpdateOptions updates the pomerium config options.
func (srv *Server) UpdateOptions(options config.Options) error {
	select {
	case <-srv.configUpdated:
	default:
	}
	prev := srv.currentConfig.Load().(versionedOptions)
	srv.currentConfig.Store(versionedOptions{
		Options: options,
		version: prev.version + 1,
	})
	srv.configUpdated <- struct{}{}
	return nil
}
