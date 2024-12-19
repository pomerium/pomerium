package trace

import (
	"context"
	"fmt"
	"net/http"

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

func NewStatsHandler(base stats.Handler) stats.Handler {
	return &statsHandlerWrapper{
		base: base,
	}
}

type statsHandlerWrapper struct {
	base stats.Handler
}

func (w *statsHandlerWrapper) wrapContext(ctx context.Context) context.Context {
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
func (w *statsHandlerWrapper) HandleConn(ctx context.Context, stats stats.ConnStats) {
	w.base.HandleConn(w.wrapContext(ctx), stats)
}

// HandleRPC implements stats.Handler.
func (w *statsHandlerWrapper) HandleRPC(ctx context.Context, stats stats.RPCStats) {
	w.base.HandleRPC(w.wrapContext(ctx), stats)
}

// TagConn implements stats.Handler.
func (w *statsHandlerWrapper) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	return w.base.TagConn(w.wrapContext(ctx), info)
}

// TagRPC implements stats.Handler.
func (w *statsHandlerWrapper) TagRPC(ctx context.Context, info *stats.RPCTagInfo) context.Context {
	return w.base.TagRPC(w.wrapContext(ctx), info)
}
