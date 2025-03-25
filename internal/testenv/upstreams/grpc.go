package upstreams

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/pomerium/pomerium/internal/testenv"
	"github.com/pomerium/pomerium/internal/testenv/snippets"
	"github.com/pomerium/pomerium/internal/testenv/values"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

type GRPCUpstreamOptions struct {
	CommonUpstreamOptions
	serverOpts []grpc.ServerOption
}

type GRPCUpstreamOption interface {
	applyGRPC(*GRPCUpstreamOptions)
}

type GRPCUpstreamOptionFunc func(*GRPCUpstreamOptions)

func (f GRPCUpstreamOptionFunc) applyGRPC(o *GRPCUpstreamOptions) {
	f(o)
}

func ServerOpts(opt ...grpc.ServerOption) GRPCUpstreamOption {
	return GRPCUpstreamOptionFunc(func(o *GRPCUpstreamOptions) {
		o.serverOpts = append(o.serverOpts, opt...)
	})
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

	// Dials the server directly instead of going through a Pomerium route.
	DirectConnect(dialOpts ...grpc.DialOption) *grpc.ClientConn
}

type grpcUpstream struct {
	GRPCUpstreamOptions
	testenv.Aggregate
	serverPort           values.MutableValue[int]
	creds                credentials.TransportCredentials
	serverTracerProvider values.MutableValue[oteltrace.TracerProvider]
	clientTracerProvider values.MutableValue[oteltrace.TracerProvider]

	services []service
}

var (
	_ testenv.Upstream      = (*grpcUpstream)(nil)
	_ grpc.ServiceRegistrar = (*grpcUpstream)(nil)
)

// GRPC creates a new GRPC upstream server.
func GRPC(creds credentials.TransportCredentials, opts ...GRPCUpstreamOption) GRPCUpstream {
	options := GRPCUpstreamOptions{
		CommonUpstreamOptions: CommonUpstreamOptions{
			displayName: "GRPC Upstream",
		},
	}
	for _, op := range opts {
		op.applyGRPC(&options)
	}
	up := &grpcUpstream{
		GRPCUpstreamOptions:  options,
		creds:                creds,
		serverPort:           values.Deferred[int](),
		serverTracerProvider: values.Deferred[oteltrace.TracerProvider](),
		clientTracerProvider: values.Deferred[oteltrace.TracerProvider](),
	}
	up.RecordCaller()
	return up
}

type service struct {
	desc *grpc.ServiceDesc
	impl any
}

func (g *grpcUpstream) Addr() values.Value[string] {
	return values.Bind(g.serverPort, func(port int) string {
		return fmt.Sprintf("%s:%d", g.Env().Host(), port)
	})
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
		return fmt.Sprintf("%s://%s:%d", protocol, g.Env().Host(), port)
	}))
	g.Add(r)
	return r
}

// Start implements testenv.Upstream.
func (g *grpcUpstream) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:0", g.Env().Host()))
	if err != nil {
		return err
	}
	g.serverPort.Resolve(listener.Addr().(*net.TCPAddr).Port)
	if g.serverTracerProviderOverride != nil {
		g.serverTracerProvider.Resolve(g.serverTracerProviderOverride)
	} else {
		g.serverTracerProvider.Resolve(trace.NewTracerProvider(ctx, g.displayName))
	}
	if g.clientTracerProviderOverride != nil {
		g.clientTracerProvider.Resolve(g.clientTracerProviderOverride)
	} else {
		g.clientTracerProvider.Resolve(trace.NewTracerProvider(ctx, "GRPC Client"))
	}
	server := grpc.NewServer(append(g.serverOpts,
		grpc.Creds(g.creds),
		grpc.StatsHandler(otelgrpc.NewServerHandler(
			otelgrpc.WithTracerProvider(g.serverTracerProvider.Value()),
		)),
	)...)
	for _, s := range g.services {
		server.RegisterService(s.desc, s.impl)
	}
	if g.delayShutdown {
		return snippets.RunWithDelayedShutdown(ctx,
			func() error {
				return server.Serve(listener)
			},
			server.GracefulStop,
		)()
	}
	errC := make(chan error, 1)
	go func() {
		errC <- server.Serve(listener)
	}()
	select {
	case <-ctx.Done():
		server.GracefulStop()
		return context.Cause(ctx)
	case err := <-errC:
		return err
	}
}

func (g *grpcUpstream) withDefaultDialOpts(extraDialOpts []grpc.DialOption) []grpc.DialOption {
	return append(extraDialOpts,
		grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(g.Env().ServerCAs(), "")),
		grpc.WithDefaultCallOptions(grpc.WaitForReady(true)),
		grpc.WithStatsHandler(otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(g.clientTracerProvider.Value()))),
	)
}

func (g *grpcUpstream) Dial(r testenv.Route, dialOpts ...grpc.DialOption) *grpc.ClientConn {
	cc, err := grpc.NewClient(strings.TrimPrefix(r.URL().Value(), "https://"), g.withDefaultDialOpts(dialOpts)...)
	if err != nil {
		panic(err)
	}
	return cc
}

func (g *grpcUpstream) DirectConnect(dialOpts ...grpc.DialOption) *grpc.ClientConn {
	cc, err := grpc.NewClient(g.Addr().Value(),
		append(g.withDefaultDialOpts(dialOpts), grpc.WithTransportCredentials(insecure.NewCredentials()))...)
	if err != nil {
		panic(err)
	}
	return cc
}
