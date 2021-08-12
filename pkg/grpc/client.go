package grpc

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/pkg/grpcutil"
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
		unaryClientInterceptors = append(unaryClientInterceptors, grpcutil.WithUnarySignedJWT(opts.SignedJWTKey))
		streamClientInterceptors = append(streamClientInterceptors, grpcutil.WithStreamSignedJWT(opts.SignedJWTKey))
	}

	dialOptions := []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(unaryClientInterceptors...),
		grpc.WithChainStreamInterceptor(streamClientInterceptors...),
		grpc.WithDefaultCallOptions([]grpc.CallOption{grpc.WaitForReady(true)}...),
		grpc.WithStatsHandler(clientStatsHandler.Handler),
		grpc.WithDisableServiceConfig(),
		grpc.WithInsecure(),
	}
	dialOptions = append(dialOptions, other...)
	log.Info(ctx).Str("address", opts.Address).Msg("dialing")
	return grpc.DialContext(ctx, opts.Address, dialOptions...)
}

// grpcTimeoutInterceptor enforces per-RPC request timeouts
func grpcTimeoutInterceptor(timeout time.Duration) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply interface{}, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		if timeout <= 0 {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

type grpcClientConnRecord struct {
	conn *grpc.ClientConn
	opts *Options
}

var grpcClientConns = struct {
	sync.Mutex
	m map[string]grpcClientConnRecord
}{
	m: make(map[string]grpcClientConnRecord),
}

// GetGRPCClientConn returns a gRPC client connection for the given name. If a connection for that name has already been
// established the existing connection will be returned. If any options change for that connection, the existing
// connection will be closed and a new one established.
func GetGRPCClientConn(ctx context.Context, name string, opts *Options) (*grpc.ClientConn, error) {
	grpcClientConns.Lock()
	defer grpcClientConns.Unlock()

	current, ok := grpcClientConns.m[name]
	if ok {
		if cmp.Equal(current.opts, opts) {
			return current.conn, nil
		}

		err := current.conn.Close()
		if err != nil {
			log.Error(context.TODO()).Err(err).Msg("grpc: failed to close existing connection")
		}
	}

	cc, err := NewGRPCClientConn(ctx, opts)
	if err != nil {
		return nil, err
	}

	grpcClientConns.m[name] = grpcClientConnRecord{
		conn: cc,
		opts: opts,
	}
	return cc, nil
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

// GetOutboundGRPCClientConn gets the outbound gRPC client.
func GetOutboundGRPCClientConn(ctx context.Context, opts *OutboundOptions) (*grpc.ClientConn, error) {
	return GetGRPCClientConn(ctx, "outbound", &Options{
		Address:        net.JoinHostPort("127.0.0.1", opts.OutboundPort),
		InstallationID: opts.InstallationID,
		ServiceName:    opts.ServiceName,
		SignedJWTKey:   opts.SignedJWTKey,
	})
}
