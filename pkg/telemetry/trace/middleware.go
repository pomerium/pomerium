package trace

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/gorilla/mux"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"google.golang.org/grpc/stats"
)

func NewHTTPMiddleware(opts ...otelhttp.Option) func(http.Handler) http.Handler {
	return otelhttp.NewMiddleware("Server: %s %s", append(opts, otelhttp.WithSpanNameFormatter(func(operation string, r *http.Request) string {
		routeStr := ""
		if route := mux.CurrentRoute(r); route != nil {
			var err error
			routeStr, err = route.GetPathTemplate()
			if err != nil {
				routeStr, err = route.GetPathRegexp()
				if err != nil {
					routeStr = ""
				}
			}
		} else {
			routeStr = r.Pattern
		}
		return fmt.Sprintf(operation, r.Method, routeStr)
	}))...)
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
