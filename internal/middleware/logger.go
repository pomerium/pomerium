package middleware // import "github.com/pomerium/pomerium/internal/middleware"

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/rs/zerolog"
)

// FromRequest gets the logger in the request's context.
// This is a shortcut for log.Ctx(r.Context())
func FromRequest(r *http.Request) *zerolog.Logger {
	return log.Ctx(r.Context())
}

// NewHandler injects log into requests context.
func NewHandler(log zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create a copy of the logger (including internal context slice)
			// to prevent data race when using UpdateContext.
			l := log.With().Logger()
			r = r.WithContext(l.WithContext(r.Context()))
			next.ServeHTTP(w, r)
		})
	}
}

// URLHandler adds the requested URL as a field to the context's logger
// using fieldKey as field key.
func URLHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log := zerolog.Ctx(r.Context())
			log.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str(fieldKey, r.URL.String())
			})
			next.ServeHTTP(w, r)
		})
	}
}

// MethodHandler adds the request method as a field to the context's logger
// using fieldKey as field key.
func MethodHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log := zerolog.Ctx(r.Context())
			log.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str(fieldKey, r.Method)
			})
			next.ServeHTTP(w, r)
		})
	}
}

// RequestHandler adds the request method and URL as a field to the context's logger
// using fieldKey as field key.
func RequestHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			log := zerolog.Ctx(r.Context())
			log.UpdateContext(func(c zerolog.Context) zerolog.Context {
				return c.Str(fieldKey, r.Method+" "+r.URL.String())
			})
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

type idKey struct{}

// IDFromRequest returns the unique id associated to the request if any.
func IDFromRequest(r *http.Request) (id string, ok bool) {
	if r == nil {
		return
	}
	return IDFromCtx(r.Context())
}

// IDFromCtx returns the unique id associated to the context if any.
func IDFromCtx(ctx context.Context) (id string, ok bool) {
	id, ok = ctx.Value(idKey{}).(string)
	return
}

// RequestIDHandler returns a handler setting a unique id to the request which can
// be gathered using IDFromRequest(req). This generated id is added as a field to the
// logger using the passed fieldKey as field name. The id is also added as a response
// header if the headerName is not empty.
func RequestIDHandler(fieldKey, headerName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			id, ok := IDFromRequest(r)
			if !ok {
				id = uuid()
				ctx = context.WithValue(ctx, idKey{}, id)
				r = r.WithContext(ctx)
			}
			if fieldKey != "" {
				log := zerolog.Ctx(ctx)
				log.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, id)
				})
			}
			if headerName != "" {
				w.Header().Set(headerName, id)
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
			lw := NewWrapResponseWriter(w, 2)
			next.ServeHTTP(lw, r)
			f(r, lw.Status(), lw.BytesWritten(), time.Since(start))
		})
	}
}

// ForwardedAddrHandler returns the client IP address from a request. If present, the
// X-Forwarded-For header is assumed to be set by a load balancer, and its
// rightmost entry (the client IP that connected to the LB) is returned.
func ForwardedAddrHandler(fieldKey string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr := r.RemoteAddr
			if ra := r.Header.Get("X-Forwarded-For"); ra != "" {
				forwardedList := strings.Split(ra, ",")
				forwardedAddr := strings.TrimSpace(forwardedList[len(forwardedList)-1])
				if forwardedAddr != "" {
					addr = forwardedAddr
				}
				log := zerolog.Ctx(r.Context())
				log.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str(fieldKey, addr)
				})
			}
			next.ServeHTTP(w, r)
		})
	}
}

// uuid generates a random 128-bit non-RFC UUID.
func uuid() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return ""
	}
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:])
}
