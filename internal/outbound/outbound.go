// Package outbound implements the transport for Pomerium's own outbound HTTP
// requests, such as calls to the identity provider.
package outbound

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpproxy"

	"github.com/pomerium/pomerium/internal/log"
)

// errProxyChanged is returned by a dial that completes after the proxy
// settings changed.
var errProxyChanged = errors.New("outbound: proxy settings changed during dial")

// Settings are the settings of Pomerium's own outbound HTTP requests.
type Settings struct {
	// Proxy chooses the proxy for each request.
	Proxy httpproxy.Config
	// ProxyErr, if not nil, is the error that fails every request, so that no
	// request bypasses a misconfigured proxy. It is set when the proxy
	// settings are invalid.
	ProxyErr error
	// RootCAs are the CAs that verify server certificates. Nil means the
	// system pool.
	RootCAs *x509.CertPool
}

// proxyFunc returns the function that chooses the proxy for a request
// according to s.
func (s Settings) proxyFunc() func(*http.Request) (*url.URL, error) {
	if s.ProxyErr != nil {
		invalid := s.ProxyErr
		return func(*http.Request) (*url.URL, error) { return nil, invalid }
	}
	proxyURL := s.Proxy.ProxyFunc()
	return func(req *http.Request) (*url.URL, error) {
		return proxyURL(req.URL)
	}
}

// proxyChanged reports whether the proxy settings of s and next differ.
// ProxyErr is compared by presence: an invalid value is distinct from the
// same value taken from the environment, which is not rejected.
func (s Settings) proxyChanged(next Settings) bool {
	return s.Proxy != next.Proxy || (s.ProxyErr != nil) != (next.ProxyErr != nil)
}

// HTTP holds the settings of Pomerium's own outbound HTTP requests and the
// transport that uses them. It tracks the connections dialed by its
// transport, and by every clone of it, and closes them when the proxy
// settings change, so that requests on pooled connections do not keep using
// the previous proxy. Requests using a closed connection fail, as they would
// if the network dropped the connection.
type HTTP struct {
	state     atomic.Pointer[state]
	dialer    net.Dialer
	transport *http.Transport

	mu         sync.Mutex
	generation uint64
	conns      map[*conn]struct{}
}

// state is the current settings of an [HTTP].
type state struct {
	Settings
	proxy func(*http.Request) (*url.URL, error)
}

// New creates an HTTP with the zero [Settings]: no proxy and the system CA
// pool.
func New() *HTTP {
	o := &HTTP{
		dialer: net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second},
		conns:  make(map[*conn]struct{}),
	}
	o.state.Store(&state{proxy: Settings{}.proxyFunc()})

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = o.Proxy
	transport.DialContext = o.dial
	transport.DialTLSContext = o.dialTLS
	transport.ForceAttemptHTTP2 = true
	o.transport = transport
	return o
}

// Transport returns the transport for Pomerium's own outbound HTTP requests.
// The transport and its clones use the proxy chosen by [HTTP.Proxy] and the
// current CA pool.
func (o *HTTP) Transport() *http.Transport {
	return o.transport
}

// Proxy returns the proxy for req according to the current settings.
func (o *HTTP) Proxy(req *http.Request) (*url.URL, error) {
	return o.state.Load().proxy(req)
}

// Update replaces the settings. If the proxy settings change, it closes the
// connections dialed under the previous settings.
func (o *HTTP) Update(ctx context.Context, s Settings) {
	next := &state{Settings: s, proxy: s.proxyFunc()}
	changed := o.state.Load().proxyChanged(s)

	var stale map[*conn]struct{}
	o.mu.Lock()
	// The state is stored before the generation changes, so a dial that
	// starts under the new generation follows a proxy decision that may
	// already use the new state.
	o.state.Store(next)
	if changed {
		o.generation++
		stale, o.conns = o.conns, make(map[*conn]struct{})
	}
	o.mu.Unlock()

	if len(stale) == 0 {
		return
	}
	log.Ctx(ctx).Debug().Int("connections", len(stale)).
		Msg("outbound: proxy settings changed, closing outbound connections")
	for c := range stale {
		c.Conn.Close()
	}
}

// dial dials a TCP connection, to a proxy or to an origin, and tracks it
// until it is closed or the proxy settings change.
func (o *HTTP) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	o.mu.Lock()
	generation := o.generation
	o.mu.Unlock()

	nc, err := o.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}

	o.mu.Lock()
	defer o.mu.Unlock()
	if o.generation != generation {
		nc.Close()
		return nil, errProxyChanged
	}
	c := &conn{Conn: nc, owner: o}
	o.conns[c] = struct{}{}
	return c, nil
}

// dialTLS dials a TLS connection to an origin, verified against the current
// CA pool.
func (o *HTTP) dialTLS(ctx context.Context, network, addr string) (net.Conn, error) {
	nc, err := o.dial(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	tlsConn := tls.Client(nc, &tls.Config{
		RootCAs:    o.state.Load().RootCAs,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		nc.Close()
		return nil, err
	}
	return tlsConn, nil
}

// conn is a connection tracked by an [HTTP].
type conn struct {
	net.Conn
	owner     *HTTP
	closeOnce sync.Once
}

// Close closes the connection and stops tracking it.
func (c *conn) Close() error {
	c.closeOnce.Do(func() {
		c.owner.mu.Lock()
		delete(c.owner.conns, c)
		c.owner.mu.Unlock()
	})
	return c.Conn.Close()
}
