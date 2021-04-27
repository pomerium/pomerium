package grpc

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry"
	"github.com/pomerium/pomerium/internal/telemetry/requestid"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

const (
	defaultGRPCSecurePort   = 443
	defaultGRPCInsecurePort = 80
)

// Options contains options for connecting to a pomerium rpc service.
type Options struct {
	// Addrs is the location of the service.  e.g. "service.corp.example:8443"
	Addrs []*url.URL
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

	// WithInsecure disables transport security for this ClientConn.
	// Note that transport security is required unless WithInsecure is set.
	WithInsecure bool

	// InstallationID specifies the installation id for telemetry exposition.
	InstallationID string

	// ServiceName specifies the service name for telemetry exposition
	ServiceName string

	// SignedJWTKey is the JWT key to use for signing a JWT attached to metadata.
	SignedJWTKey []byte
}

// NewGRPCClientConn returns a new gRPC pomerium service client connection.
func NewGRPCClientConn(opts *Options, other ...grpc.DialOption) (*grpc.ClientConn, error) {
	ctx := context.TODO()
	if len(opts.Addrs) == 0 {
		return nil, errors.New("internal/grpc: connection address required")
	}

	var addrs []string
	for _, u := range opts.Addrs {
		hostport := u.Host
		// no colon exists in the connection string, assume one must be added manually
		if _, _, err := net.SplitHostPort(hostport); err != nil {
			if u.Scheme == "https" {
				hostport = net.JoinHostPort(hostport, strconv.Itoa(defaultGRPCSecurePort))
			} else {
				hostport = net.JoinHostPort(hostport, strconv.Itoa(defaultGRPCInsecurePort))
			}
		}
		addrs = append(addrs, hostport)
	}

	connAddr := "pomerium:///" + strings.Join(addrs, ",")

	clientStatsHandler := telemetry.NewGRPCClientStatsHandler(opts.ServiceName)

	unaryClientInterceptors := []grpc.UnaryClientInterceptor{
		requestid.UnaryClientInterceptor(),
		grpcTimeoutInterceptor(opts.RequestTimeout),
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
		grpc.WithDefaultServiceConfig(roundRobinServiceConfig),
		grpc.WithDisableServiceConfig(),
	}

	dialOptions = append(dialOptions, other...)

	if opts.WithInsecure {
		log.Info(ctx).Str("addr", connAddr).Msg("internal/grpc: grpc with insecure")
		dialOptions = append(dialOptions, grpc.WithInsecure())
	} else {
		rootCAs, err := cryptutil.GetCertPool(opts.CA, opts.CAFile)
		if err != nil {
			return nil, err
		}

		cert := credentials.NewTLS(&tls.Config{RootCAs: rootCAs, MinVersion: tls.VersionTLS12})

		// override allowed certificate name string, typically used when doing behind ingress connection
		if opts.OverrideCertificateName != "" {
			log.Debug(ctx).Str("cert-override-name", opts.OverrideCertificateName).Msg("internal/grpc: grpc")
			err := cert.OverrideServerName(opts.OverrideCertificateName)
			if err != nil {
				return nil, err
			}
		}
		// finally add our credential
		dialOptions = append(dialOptions, grpc.WithTransportCredentials(cert))
	}

	return grpc.Dial(connAddr, dialOptions...)
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
func GetGRPCClientConn(name string, opts *Options) (*grpc.ClientConn, error) {
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

	cc, err := NewGRPCClientConn(opts)
	if err != nil {
		return nil, err
	}

	grpcClientConns.m[name] = grpcClientConnRecord{
		conn: cc,
		opts: opts,
	}
	return cc, nil
}
