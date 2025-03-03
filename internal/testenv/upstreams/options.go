package upstreams

import (
	oteltrace "go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

type CommonUpstreamOptions struct {
	displayName                  string
	clientTracerProviderOverride oteltrace.TracerProvider
	serverTracerProviderOverride oteltrace.TracerProvider
	delayShutdown                bool
}

type CommonUpstreamOption interface {
	GRPCUpstreamOption
	HTTPUpstreamOption
	TCPUpstreamOption
}

type commonUpstreamOption func(o *CommonUpstreamOptions)

// applyGRPC implements CommonUpstreamOption.
func (c commonUpstreamOption) applyGRPC(o *GRPCUpstreamOptions) { c(&o.CommonUpstreamOptions) }

// applyHTTP implements CommonUpstreamOption.
func (c commonUpstreamOption) applyHTTP(o *HTTPUpstreamOptions) { c(&o.CommonUpstreamOptions) }

// applyTCP implements CommonUpstreamOption.
func (c commonUpstreamOption) applyTCP(o *TCPUpstreamOptions) { c(&o.CommonUpstreamOptions) }

func WithDisplayName(displayName string) CommonUpstreamOption {
	return commonUpstreamOption(func(o *CommonUpstreamOptions) {
		o.displayName = displayName
	})
}

func WithNoClientTracing() CommonUpstreamOption {
	return commonUpstreamOption(func(o *CommonUpstreamOptions) {
		o.clientTracerProviderOverride = noop.NewTracerProvider()
	})
}

func WithNoServerTracing() CommonUpstreamOption {
	return commonUpstreamOption(func(o *CommonUpstreamOptions) {
		o.serverTracerProviderOverride = noop.NewTracerProvider()
	})
}

func WithClientTracerProvider(tp oteltrace.TracerProvider) CommonUpstreamOption {
	return commonUpstreamOption(func(o *CommonUpstreamOptions) {
		o.clientTracerProviderOverride = tp
	})
}

func WithServerTracerProvider(tp oteltrace.TracerProvider) CommonUpstreamOption {
	return commonUpstreamOption(func(o *CommonUpstreamOptions) {
		o.serverTracerProviderOverride = tp
	})
}

// WithDelayedShutdown keeps the server alive until the test environment has
// fully shut down, instead of stopping it during the shutdown sequence.
func WithDelayedShutdown() CommonUpstreamOption {
	return commonUpstreamOption(func(o *CommonUpstreamOptions) {
		o.delayShutdown = true
	})
}
