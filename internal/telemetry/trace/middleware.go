package trace

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
)

func NewHTTPMiddleware(opts ...otelhttp.Option) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			routeStr := ""
			route := mux.CurrentRoute(r)
			if route != nil {
				var err error
				routeStr, err = route.GetPathTemplate()
				if err != nil {
					routeStr, err = route.GetPathRegexp()
					if err != nil {
						routeStr = ""
					}
				}
			}
			traceparent := r.Header.Get("Traceparent")
			if traceparent != "" {
				xPomeriumTraceparent := r.Header.Get("X-Pomerium-Traceparent")
				if xPomeriumTraceparent != "" {
					sc, err := ParseTraceparent(xPomeriumTraceparent)
					if err == nil {
						r.Header.Set("Traceparent", WithTraceFromSpanContext(traceparent, sc))
						ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
						r = r.WithContext(ctx)
					}
				}
			}
			otelhttp.NewHandler(next, fmt.Sprintf("Server: %s %s", r.Method, routeStr), opts...).ServeHTTP(w, r)
		})
	}
}

func NewServerStatsHandler(base stats.Handler) stats.Handler {
	return &serverStatsHandlerWrapper{
		base: base,
	}
}

type serverStatsHandlerWrapper struct {
	base stats.Handler
}

func (w *serverStatsHandlerWrapper) wrapContext(ctx context.Context) context.Context {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	traceparent := md.Get("traceparent")
	xPomeriumTraceparent := md.Get("x-pomerium-traceparent")
	if len(traceparent) > 0 && traceparent[0] != "" && len(xPomeriumTraceparent) > 0 && xPomeriumTraceparent[0] != "" {
		newTracectx, err := ParseTraceparent(xPomeriumTraceparent[0])
		if err != nil {
			return ctx
		}

		md.Set("traceparent", WithTraceFromSpanContext(traceparent[0], newTracectx))
		return metadata.NewIncomingContext(ctx, md)
	}
	return ctx
}

// HandleConn implements stats.Handler.
func (w *serverStatsHandlerWrapper) HandleConn(ctx context.Context, stats stats.ConnStats) {
	w.base.HandleConn(w.wrapContext(ctx), stats)
}

// HandleRPC implements stats.Handler.
func (w *serverStatsHandlerWrapper) HandleRPC(ctx context.Context, stats stats.RPCStats) {
	w.base.HandleRPC(w.wrapContext(ctx), stats)
}

// TagConn implements stats.Handler.
func (w *serverStatsHandlerWrapper) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	return w.base.TagConn(w.wrapContext(ctx), info)
}

// TagRPC implements stats.Handler.
func (w *serverStatsHandlerWrapper) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return w.base.TagRPC(w.wrapContext(ctx), info)
}

type clientStatsHandlerWrapper struct {
	ClientStatsHandlerOptions
	base stats.Handler
}

type ClientStatsHandlerOptions struct {
	statsInterceptor func(ctx context.Context, rs stats.RPCStats) stats.RPCStats
}

type ClientStatsHandlerOption func(*ClientStatsHandlerOptions)

func (o *ClientStatsHandlerOptions) apply(opts ...ClientStatsHandlerOption) {
	for _, op := range opts {
		op(o)
	}
}

// WithStatsInterceptor calls the given function to modify the rpc stats before
// passing it to the stats handler during HandleRPC events.
//
// The interceptor MUST NOT modify the RPCStats it is given. It should instead
// return a copy of the underlying object with the same type, with any
// modifications made to the copy.
func WithStatsInterceptor(statsInterceptor func(ctx context.Context, rs stats.RPCStats) stats.RPCStats) ClientStatsHandlerOption {
	return func(o *ClientStatsHandlerOptions) {
		o.statsInterceptor = statsInterceptor
	}
}

func NewClientStatsHandler(base stats.Handler, opts ...ClientStatsHandlerOption) stats.Handler {
	options := ClientStatsHandlerOptions{}
	options.apply(opts...)
	return &clientStatsHandlerWrapper{
		ClientStatsHandlerOptions: options,
		base:                      base,
	}
}

// HandleConn implements stats.Handler.
func (w *clientStatsHandlerWrapper) HandleConn(ctx context.Context, stats stats.ConnStats) {
	w.base.HandleConn(ctx, stats)
}

// HandleRPC implements stats.Handler.
func (w *clientStatsHandlerWrapper) HandleRPC(ctx context.Context, stats stats.RPCStats) {
	if w.statsInterceptor != nil {
		modified := w.statsInterceptor(ctx, stats)
		if reflect.TypeOf(stats) != reflect.TypeOf(modified) {
			panic("bug: stats interceptor returned a message of a different type")
		}
		w.base.HandleRPC(ctx, modified)
	} else {
		w.base.HandleRPC(ctx, stats)
	}
}

// TagConn implements stats.Handler.
func (w *clientStatsHandlerWrapper) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	return w.base.TagConn(ctx, info)
}

// TagRPC implements stats.Handler.
func (w *clientStatsHandlerWrapper) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return w.base.TagRPC(ctx, info)
}
