package httputil // import "github.com/pomerium/pomerium/internal/httputil"

import (
	stdlog "log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/pomerium/pomerium/internal/log"
)

// HeaderForwardHost is the header key that identifies the original host requested
// by the client in the Host HTTP request header.
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-Host
const HeaderForwardHost = "X-Forwarded-Host"

// NewReverseProxy returns a new ReverseProxy that routes
// URLs to the scheme, host, and base path provided in target,
// rewrites the Host header, and sets `X-Forwarded-Host`.
func NewReverseProxy(target *url.URL) *httputil.ReverseProxy {
	reverseProxy := httputil.NewSingleHostReverseProxy(target)
	sublogger := log.With().Str("reverse-proxy", target.Host).Logger()
	reverseProxy.ErrorLog = stdlog.New(&log.StdLogWrapper{Logger: &sublogger}, "", 0)
	director := reverseProxy.Director
	reverseProxy.Director = func(req *http.Request) {
		req.Header.Add(HeaderForwardHost, req.Host)
		director(req)
		req.Host = target.Host
	}
	return reverseProxy
}
