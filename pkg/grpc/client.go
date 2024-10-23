package grpc

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

// Options contains options for connecting to a pomerium rpc service.
type Options struct {
	// Address is the location of the service.  e.g. "service.corp.example:8443"
	Address string

	// InstallationID specifies the installation id for telemetry exposition.
	InstallationID string

	// ServiceName specifies the service name for telemetry exposition
	ServiceName string

	// SignedJWTKey is the JWT key to use for signing a JWT attached to metadata.
	SignedJWTKey []byte
}

// NewGRPCClientConn returns a new gRPC pomerium service client connection.
func NewGRPCClientConn(ctx context.Context, opts *Options, other ...grpc.DialOption) (*grpc.ClientConn, error) {
	clientStatsHandler := telemetry.NewGRPCClientStatsHandler(opts.ServiceName)

	unaryClientInterceptors := []grpc.UnaryClientInterceptor{
		requestid.UnaryClientInterceptor(),
		clientStatsHandler.UnaryInterceptor,
	}
	streamClientInterceptors := []grpc.StreamClientInterceptor{
		requestid.StreamClientInterceptor(),
	}
	if opts.SignedJWTKey != nil {
		unaryClientInterceptors = append(unaryClientInterceptors, grpcutil.WithUnarySignedJWT(func() []byte { return opts.SignedJWTKey }))
		streamClientInterceptors = append(streamClientInterceptors, grpcutil.WithStreamSignedJWT(func() []byte { return opts.SignedJWTKey }))
	}

	dialOptions := []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(unaryClientInterceptors...),
		grpc.WithChainStreamInterceptor(streamClientInterceptors...),
		grpc.WithStatsHandler(clientStatsHandler.Handler),
		grpc.WithDisableServiceConfig(),
		grpc.WithInsecure(),
	}
	dialOptions = append(dialOptions, other...)
	log.Ctx(ctx).Debug().Str("address", opts.Address).Msg("grpc: dialing")
	return grpc.DialContext(ctx, opts.Address, dialOptions...)
}

// grpcTimeoutInterceptor enforces per-RPC request timeouts
func grpcTimeoutInterceptor(timeout time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if timeout <= 0 {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// OutboundOptions are the options for the outbound gRPC client.
type OutboundOptions struct {
	// OutboundPort is the port for the outbound gRPC listener.
	OutboundPort string

	// InstallationID specifies the installation id for telemetry exposition.
	InstallationID string

	// ServiceName specifies the service name for telemetry exposition
	ServiceName string

	// SignedJWTKey is the JWT key to use for signing a JWT attached to metadata.
	SignedJWTKey []byte
}

// newOutboundGRPCClientConn gets a new outbound gRPC client.
func newOutboundGRPCClientConn(ctx context.Context, opts *OutboundOptions) (*grpc.ClientConn, error) {
	return NewGRPCClientConn(ctx, &Options{
		Address:        net.JoinHostPort("127.0.0.1", opts.OutboundPort),
		InstallationID: opts.InstallationID,
		ServiceName:    opts.ServiceName,
		SignedJWTKey:   opts.SignedJWTKey,
	})
}

// CachedOutboundGRPClientConn keeps a cached outbound gRPC client connection open based on options.
type CachedOutboundGRPClientConn struct {
	mu      sync.Mutex
	opts    *OutboundOptions
	current *grpc.ClientConn
}

// Get gets the cached outbound gRPC client, or creates a new one if the options have changed.
func (cache *CachedOutboundGRPClientConn) Get(ctx context.Context, opts *OutboundOptions) (*grpc.ClientConn, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if cache.current != nil && cmp.Equal(cache.opts, opts) {
		return cache.current, nil
	}

	if cache.current != nil {
		_ = cache.current.Close()
		cache.current = nil
	}

	var err error
	cache.current, err = newOutboundGRPCClientConn(ctx, opts)
	if err != nil {
		return nil, err
	}
	cache.opts = opts
	return cache.current, nil
}

// WaitForReady waits for the connection to be ready.
func WaitForReady(ctx context.Context, cc *grpc.ClientConn, timeout time.Duration) error {
	if cc.GetState() == connectivity.Ready {
		return nil
	}

	ctx, clearTimeout := context.WithTimeout(ctx, timeout)
	defer clearTimeout()

	cc.Connect()
	ticker := time.NewTicker(time.Millisecond * 50)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}

		if cc.GetState() == connectivity.Ready {
			return nil
		}
	}
}
