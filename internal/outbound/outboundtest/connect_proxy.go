// Package outboundtest provides test helpers for Pomerium's outbound HTTP
// requests.
package outboundtest

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ConnectProxy is an HTTP CONNECT proxy that records the authority of every
// CONNECT request it receives.
type ConnectProxy struct {
	*httptest.Server

	mu      sync.Mutex
	targets []string
	tunnels []net.Conn
}

// NewConnectProxy starts a ConnectProxy that tunnels each CONNECT request
// through dial. It is stopped when the test ends.
func NewConnectProxy(t *testing.T, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *ConnectProxy {
	t.Helper()
	p := &ConnectProxy{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "only CONNECT is supported", http.StatusMethodNotAllowed)
			return
		}
		p.mu.Lock()
		p.targets = append(p.targets, r.Host)
		p.mu.Unlock()

		upstream, err := dial(r.Context(), "tcp", r.Host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer upstream.Close()
		client, brw, err := http.NewResponseController(w).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		p.mu.Lock()
		p.tunnels = append(p.tunnels, client, upstream)
		p.mu.Unlock()

		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		go func() { _, _ = io.Copy(upstream, brw) }()
		_, _ = io.Copy(client, upstream)
	}))
	// Hijacked connections outlive Server.Close, so close them explicitly.
	t.Cleanup(func() {
		p.Close()
		p.mu.Lock()
		defer p.mu.Unlock()
		for _, conn := range p.tunnels {
			conn.Close()
		}
	})
	return p
}

// Connects returns the number of tunnels requested to a host whose name
// starts with prefix.
func (p *ConnectProxy) Connects(prefix string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for _, target := range p.targets {
		if strings.HasPrefix(target, prefix) {
			n++
		}
	}
	return n
}

// ClearProxyEnv sets the proxy environment variables to empty values for the
// duration of the test.
func ClearProxyEnv(t *testing.T) {
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(key, "")
	}
}
