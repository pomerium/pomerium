package upstreams

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type Options struct {
	serverOpts []grpc.ServerOption
}

type Option func(*Options)

func (o *Options) apply(opts ...Option) {
	for _, op := range opts {
		op(o)
	}
}

func ServerOpts(opt ...grpc.ServerOption) Option {
	return func(o *Options) {
		o.serverOpts = append(o.serverOpts, opt...)
	}
}

// GRPCUpstream represents a GRPC server which can be used as the target for
// one or more Pomerium routes in a test environment.
//
// This upstream implements [grpc.ServiceRegistrar], and can be used similarly
// in the same way as [*grpc.Server] to register services before it is started.
//
// Any [testenv.Route] instances created from this upstream can be referenced
// in the Dial() method to establish a connection to that route.
type GRPCUpstream interface {
	testenv.Upstream
	grpc.ServiceRegistrar
	Dial(r testenv.Route, dialOpts ...grpc.DialOption) *grpc.ClientConn
}

type grpcUpstream struct {
	Options
	testenv.Aggregate
	serverPort values.MutableValue[int]
	creds      credentials.TransportCredentials

	services []service
}

var (
	_ testenv.Upstream      = (*grpcUpstream)(nil)
	_ grpc.ServiceRegistrar = (*grpcUpstream)(nil)
)

// GRPC creates a new GRPC upstream server.
func GRPC(creds credentials.TransportCredentials, opts ...Option) GRPCUpstream {
	options := Options{}
	options.apply(opts...)
	up := &grpcUpstream{
		Options:    options,
		creds:      creds,
		serverPort: values.Deferred[int](),
	}
	up.RecordCaller()
	return up
}

type service struct {
	desc *grpc.ServiceDesc
	impl any
}

func (g *grpcUpstream) Port() values.Value[int] {
	return g.serverPort
}

// RegisterService implements grpc.ServiceRegistrar.
func (g *grpcUpstream) RegisterService(desc *grpc.ServiceDesc, impl any) {
	g.services = append(g.services, service{desc, impl})
}

// Route implements testenv.Upstream.
func (g *grpcUpstream) Route() testenv.RouteStub {
	r := &testenv.PolicyRoute{}
	var protocol string
	switch g.creds.Info().SecurityProtocol {
	case "insecure":
		protocol = "h2c"
	default:
		protocol = "https"
	}
	r.To(values.Bind(g.serverPort, func(port int) string {
		return fmt.Sprintf("%s://127.0.0.1:%d", protocol, port)
	}))
	g.Add(r)
	return r
}

// Start implements testenv.Upstream.
func (g *grpcUpstream) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	g.serverPort.Resolve(listener.Addr().(*net.TCPAddr).Port)
	server := grpc.NewServer(append(g.serverOpts, grpc.Creds(g.creds))...)
	for _, s := range g.services {
		server.RegisterService(s.desc, s.impl)
	}
	errC := make(chan error, 1)
	go func() {
		errC <- server.Serve(listener)
	}()
	select {
	case <-ctx.Done():
		server.Stop()
		return context.Cause(ctx)
	case err := <-errC:
		return err
	}
}

func (g *grpcUpstream) Dial(r testenv.Route, dialOpts ...grpc.DialOption) *grpc.ClientConn {
	dialOpts = append(dialOpts,
		grpc.WithContextDialer(testenv.GRPCContextDialer),
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(g.Env().ServerCAs(), "")),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
	)
	cc, err := grpc.NewClient(strings.TrimPrefix(r.URL().Value(), "https://"), dialOpts...)
	if err != nil {
		panic(err)
	}
	return cc
}
