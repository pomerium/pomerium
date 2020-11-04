package config

import (
	"crypto/tls"
	"net/http"
	"sync/atomic"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

type httpTransport struct {
	underlying *http.Transport
	transport  atomic.Value
}

// NewHTTPTransport creates a new http transport. If CA or CAFile is set, the transport will
// add the CA to system cert pool.
func NewHTTPTransport(src Source) http.RoundTripper {
	t := new(httpTransport)
	t.underlying, _ = http.DefaultTransport.(*http.Transport)
	src.OnConfigChange(func(cfg *Config) {
		t.update(cfg.Options)
	})
	t.update(src.GetConfig().Options)
	return t
}

func (t *httpTransport) update(options *Options) {
	nt := new(http.Transport)
	if t.underlying != nil {
		nt = t.underlying.Clone()
	}
	if options.CA != "" || options.CAFile != "" {
		rootCAs, err := cryptutil.GetCertPool(options.CA, options.CAFile)
		if err == nil {
			nt.TLSClientConfig = &tls.Config{
				RootCAs: rootCAs,
			}
		} else {
			log.Error().Err(err).Msg("internal/config: error getting cert pool")
		}
	}
	t.transport.Store(nt)
}

// RoundTrip executes an HTTP request.
func (t *httpTransport) RoundTrip(req *http.Request) (res *http.Response, err error) {
	return t.transport.Load().(http.RoundTripper).RoundTrip(req)
}
