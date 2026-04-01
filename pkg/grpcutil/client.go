package grpcutil

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

const (
	defaultGRPCSecurePort   = 443
	defaultGRPCInsecurePort = 80
)

// Options contains options for connecting to a pomerium rpc service.
type Options struct {
	// Address is the location of the service.  e.g. "service.corp.example:8443"
	Address *url.URL
	// OverrideCertificateName overrides the server name used to verify the hostname on the
	// returned certificates from the server. gRPC internals also use it to override the virtual
	// hosting name if it is set.
	OverrideCertificateName string
	// CA specifies the base64 encoded TLS certificate authority to use.
	CA string
	// CAFile specifies the TLS certificate authority file to use.
	CAFile string
	// RequestTimeout specifies the timeout for individual RPC calls
	RequestTimeout time.Duration
	// ClientDNSRoundRobin enables or disables DNS resolver based load balancing
	ClientDNSRoundRobin bool

	// InsecureSkipVerify skips destination hostname and ca check
	InsecureSkipVerify bool

	// ServiceName specifies the service name for telemetry exposition
	ServiceName string

	// SignedJWTKey is the JWT key to use for signing a JWT attached to metadata.
	SignedJWTKey []byte
}

// NewGRPCClientConn returns a new gRPC pomerium service client connection.
func NewGRPCClientConn(ctx context.Context, opts *Options, other ...grpc.DialOption) (*grpc.ClientConn, error) {
	hostport := opts.Address.Host
	// no colon exists in the connection string, assume one must be added manually
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		if opts.Address.Scheme == "https" {
			hostport = net.JoinHostPort(hostport, strconv.Itoa(defaultGRPCSecurePort))
		} else {
			hostport = net.JoinHostPort(hostport, strconv.Itoa(defaultGRPCInsecurePort))
		}
	}

	unaryClientInterceptors := []grpc.UnaryClientInterceptor{
		grpcTimeoutInterceptor(opts.RequestTimeout),
	}
	streamClientInterceptors := []grpc.StreamClientInterceptor{}
	if opts.SignedJWTKey != nil {
		unaryClientInterceptors = append(unaryClientInterceptors, WithUnarySignedJWT(func() []byte { return opts.SignedJWTKey }))
		streamClientInterceptors = append(streamClientInterceptors, WithStreamSignedJWT(func() []byte { return opts.SignedJWTKey }))
	}

	dialOptions := []grpc.DialOption{
		grpc.WithChainUnaryInterceptor(unaryClientInterceptors...),
		grpc.WithChainStreamInterceptor(streamClientInterceptors...),
		grpc.WithDefaultCallOptions([]grpc.CallOption{grpc.WaitForReady(true)}...),
		grpc.WithDisableServiceConfig(),
	}

	dialOptions = append(dialOptions, other...)

	if opts.Address.Scheme == "http" {
		dialOptions = append(dialOptions, grpc.WithInsecure())
	} else {
		rootCAs, err := cryptutil.GetCertPool(opts.CA, opts.CAFile)
		if err != nil {
			return nil, err
		}

		cert := credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: opts.InsecureSkipVerify,
			RootCAs:            rootCAs,
			MinVersion:         tls.VersionTLS12,
		})

		// override allowed certificate name string, typically used when doing behind ingress connection
		if opts.OverrideCertificateName != "" {
			err := cert.OverrideServerName(opts.OverrideCertificateName)
			if err != nil {
				return nil, err
			}
		}
		// finally add our credential
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(cert))
	}

	return grpc.DialContext(ctx, hostport, dialOptions...)
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
