package log

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/pomerium/protoutil/streams"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/middleware/responsewriter"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
)

// NewHandler injects log into requests context.
func NewHandler(getLogger func() *zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create a copy of the logger (including internal context slice)
			// to prevent data race when using UpdateContext.
			l := getLogger().With().Logger()
			r = r.WithContext(l.WithContext(r.Context()))
			next.ServeHTTP(w, r)
		})
	}
}

// RemoteAddrHandler adds the request's remote address as a field to the context's logger
// using fieldKey as field key.
func RemoteAddrHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				log := zerolog.Ctx(r.Context())
				log.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, host)
				})
			}
			next.ServeHTTP(w, r)
		})
	}
}

// UserAgentHandler adds the request's user-agent as a field to the context's logger
// using fieldKey as field key.
func UserAgentHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ua := r.Header.Get("User-Agent"); ua != "" {
				log := zerolog.Ctx(r.Context())
				log.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, ua)
				})
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RefererHandler adds the request's referer as a field to the context's logger
// using fieldKey as field key.
func RefererHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ref := r.Header.Get("Referer"); ref != "" {
				log := zerolog.Ctx(r.Context())
				log.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, ref)
				})
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequestIDHandler adds the request's id as a field to the context's logger
// using fieldKey as field key.
func RequestIDHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := requestid.FromContext(r.Context())
			if requestID != "" {
				log := zerolog.Ctx(r.Context())
				log.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, requestID)
				})
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AccessHandler returns a handler that call f after each request.
func AccessHandler(f func(r *http.Request, status, size int, duration time.Duration)) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			lw := responsewriter.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(lw, r)
			f(r, lw.Status(), lw.BytesWritten(), time.Since(start))
		})
	}
}

// HeadersHandler adds the provided set of header keys to the log context.
//
// https://tools.ietf.org/html/rfc7239
// https://en.wikipedia.org/wiki/X-Forwarded-For
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
func HeadersHandler(headers []string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, key := range headers {
				if values := r.Header[key]; len(values) != 0 {
					log := zerolog.Ctx(r.Context())
					log.UpdateContext(func(c zerolog.Context) zerolog.Context {
						return c.Strs(key, values)
					})
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func StreamServerInterceptor(lg *zerolog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		s := streams.NewServerStreamWithContext(ss)
		s.SetContext(lg.WithContext(s.Ctx))
		return handler(srv, s)
	}
}

func UnaryServerInterceptor(lg *zerolog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(lg.WithContext(ctx), req)
	}
}
