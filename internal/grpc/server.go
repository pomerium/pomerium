package grpc

import (
	"crypto/tls"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
)

// NewServer creates a new gRPC serve.
// It is the callers responsibility to close the resturned server.
func NewServer(opt *ServerOptions, registrationFn func(s *grpc.Server), wg *sync.WaitGroup) (*grpc.Server, error) {
	if opt == nil {
		opt = defaultServerOptions
	} else {
		opt.applyServerDefaults()
	}
	ln, err := net.Listen("tcp", opt.Addr)
	if err != nil {
		return nil, err
	}
	grpcOpts := []grpc.ServerOption{
		grpc.StatsHandler(metrics.NewGRPCServerStatsHandler(opt.ServiceName)),
		grpc.KeepaliveParams(opt.KeepaliveParams),
	}

	if opt.TLSCertificate != nil {
		log.Debug().Str("addr", opt.Addr).Msg("internal/grpc: serving over TLS")
		cert := credentials.NewServerTLSFromCert(opt.TLSCertificate)
		grpcOpts = append(grpcOpts, grpc.Creds(cert))
	} else {
		log.Warn().Str("addr", opt.Addr).Msg("internal/grpc: serving without TLS")
	}

	srv := grpc.NewServer(grpcOpts...)
	registrationFn(srv)
	log.Info().Interface("grpc-service-info", srv.GetServiceInfo()).Msg("internal/grpc: registered")

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := srv.Serve(ln); err != grpc.ErrServerStopped {
			log.Error().Str("addr", opt.Addr).Err(err).Msg("internal/grpc: unexpected shutdown")
		}
	}()

	return srv, nil
}

// ServerOptions contains the configurations settings for a gRPC server.
type ServerOptions struct {
	// Addr specifies the host and port on which the server should serve
	// gRPC requests. If empty, ":443" is used.
	Addr string

	// TLS certificates to use, if any.
	TLSCertificate *tls.Certificate

	// InsecureServer when enabled disables all transport security.
	// In this mode, Pomerium is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	InsecureServer bool

	// KeepaliveParams sets GRPC keepalive.ServerParameters
	KeepaliveParams keepalive.ServerParameters

	// ServiceName specifies the service name for telemetry exposition
	ServiceName string
}

var defaultServerOptions = &ServerOptions{
	Addr: ":443",
}

func (o *ServerOptions) applyServerDefaults() {
	if o.Addr == "" {
		o.Addr = defaultServerOptions.Addr
	}

}

// Shutdown attempts to shut down the server when a os interrupt or sigterm
// signal are received without interrupting any
// active connections. Shutdown stops the server from
// accepting new connections and RPCs and blocks until all the pending RPCs are
// finished.
func Shutdown(srv *grpc.Server) {
	sigint := make(chan os.Signal, 1)
	signal.Notify(sigint, os.Interrupt)
	signal.Notify(sigint, syscall.SIGTERM)
	rec := <-sigint
	log.Info().Str("signal", rec.String()).Msg("internal/grpc: shutting down servers")
	srv.GracefulStop()
	log.Info().Str("signal", rec.String()).Msg("internal/grpc: shut down servers")
}
