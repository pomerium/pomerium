package grpc

import (
	"context"
	"net/netip"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/pomerium/pomerium/internal/log"
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
	unaryClientInterceptors := []grpc.UnaryClientInterceptor{
		requestid.UnaryClientInterceptor(),
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
		grpc.WithDisableServiceConfig(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	}
	dialOptions = append(dialOptions, other...)
	log.Ctx(ctx).Debug().Str("address", opts.Address).Msg("grpc: dialing")
	return grpc.NewClient(opts.Address, dialOptions...)
}

// OutboundOptions are the options for the outbound gRPC client.
type OutboundOptions struct {
	// OutboundAddress is the address for the outbound gRPC listener.
	OutboundAddress netip.AddrPort

	// InstallationID specifies the installation id for telemetry exposition.
	InstallationID string

	// ServiceName specifies the service name for telemetry exposition
	ServiceName string

	// SignedJWTKey is the JWT key to use for signing a JWT attached to metadata.
	SignedJWTKey []byte
}

// newOutboundGRPCClientConn gets a new outbound gRPC client.
func newOutboundGRPCClientConn(ctx context.Context, opts *OutboundOptions, other ...grpc.DialOption) (*grpc.ClientConn, error) {
	return NewGRPCClientConn(ctx, &Options{
		Address:        opts.OutboundAddress.String(),
		InstallationID: opts.InstallationID,
		ServiceName:    opts.ServiceName,
		SignedJWTKey:   opts.SignedJWTKey,
	}, other...)
}

// CachedOutboundGRPClientConn keeps a cached outbound gRPC client connection open based on options.
type CachedOutboundGRPClientConn struct {
	mu          sync.Mutex
	opts        *OutboundOptions
	current     *grpc.ClientConn
	stopCleanup func() bool
}

// Get gets the cached outbound gRPC client, or creates a new one if the options have changed.
func (cache *CachedOutboundGRPClientConn) Get(ctx context.Context, opts *OutboundOptions, other ...grpc.DialOption) (*grpc.ClientConn, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if cache.current != nil && cmp.Equal(cache.opts, opts, cmpopts.EquateComparable(netip.AddrPort{}, netip.Addr{})) {
		return cache.current, nil
	}

	if cache.current != nil {
		if cache.stopCleanup() {
			_ = cache.current.Close()
		}
		cache.current = nil
	}

	var err error
	cache.current, err = newOutboundGRPCClientConn(ctx, opts, other...)
	if err != nil {
		return nil, err
	}
	cache.opts = opts

	cc := cache.current
	cache.stopCleanup = context.AfterFunc(ctx, func() {
		cc.Close()
	})
	return cache.current, nil
}
