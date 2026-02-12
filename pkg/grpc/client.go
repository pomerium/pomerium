package grpc

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

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
		grpc.WithKeepaliveParams(
			keepalive.ClientParameters{
				// !! Must be more than the grpc.Server side's keepalive enforcement policy, default 5mins
				Time:                time.Minute * 6,
				Timeout:             time.Second * 20,
				PermitWithoutStream: true,
			},
		),
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
func newOutboundGRPCClientConn(ctx context.Context, opts *OutboundOptions, other ...grpc.DialOption) (*grpc.ClientConn, error) {
	return NewGRPCClientConn(ctx, &Options{
		Address:        net.JoinHostPort("127.0.0.1", opts.OutboundPort),
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
	done        chan struct{}
	stopCleanup func() bool
}

// Get gets the cached outbound gRPC client, or creates a new one if the options have changed.
func (cache *CachedOutboundGRPClientConn) Get(ctx context.Context, opts *OutboundOptions, other ...grpc.DialOption) (*grpc.ClientConn, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()

	if cache.current != nil && cmp.Equal(cache.opts, opts) {
		return cache.current, nil
	}
	log.Ctx(ctx).Info().Msg("outbound client connection has changed meaningfully, reloading")
	if cache.current != nil {
		if cache.stopCleanup() {
			// We prevented the AfterFunc from running; close the connection ourselves.
			cache.current.Close()
		} else {
			// The AfterFunc already started; wait for it to finish closing.
			<-cache.done
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
	done := make(chan struct{}, 1)
	cache.done = done

	cache.stopCleanup = context.AfterFunc(ctx, func() {
		defer close(done)
		log.Ctx(ctx).Info().Msg("stopping outbound client connection")
		if err := cc.Close(); err != nil {
			log.Ctx(ctx).Err(err).Msg("failed to stop outbound client connection")
		}
		log.Ctx(ctx).Info().Msg("ready to create new outbound client connection")
	})
	return cache.current, nil
}
