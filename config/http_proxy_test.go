package config_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestHTTPTransportThroughProxy(t *testing.T) {
	t.Parallel()

	origin, ca := newTLSOrigin(t)

	// get requests https://host through a new proxy that tunnels every
	// CONNECT to origin.
	get := func(t *testing.T, ca, host string) error {
		t.Helper()
		proxy := newConnectProxy(t, dialTo(origin))
		transport := config.NewHTTPTransport(config.NewStaticSource(config.New(&config.Options{
			CA:            ca,
			GlobalOptions: config.GlobalOptions{OutboundHttpsProxy: nullable.From(proxy.URL)},
		})))
		t.Cleanup(transport.CloseIdleConnections)
		err := getOrigin(t, transport, origin, host)
		assert.Equal(t, 1, proxy.Connects(host), "request goes through the proxy")
		return err
	}

	t.Run("trusted certificate authority", func(t *testing.T) {
		assert.NoError(t, get(t, ca, "example.com"))
	})
	t.Run("untrusted certificate authority", func(t *testing.T) {
		err := get(t, "", "example.com")
		var unknownAuthority x509.UnknownAuthorityError
		assert.ErrorAs(t, err, &unknownAuthority)
		var verifyErr *tls.CertificateVerificationError
		assert.ErrorAs(t, err, &verifyErr)
	})
	t.Run("certificate for another host", func(t *testing.T) {
		var hostnameErr x509.HostnameError
		assert.ErrorAs(t, get(t, ca, "other.example"), &hostnameErr)
	})
	t.Run("certificate for another ip address", func(t *testing.T) {
		assert.Error(t, get(t, ca, "192.0.2.1"))
	})
}

func TestHTTPTransportThroughProxyFollowsCAChanges(t *testing.T) {
	t.Parallel()

	origin, ca := newTLSOrigin(t)
	proxy := newConnectProxy(t, dialTo(origin))
	configWithCA := func(ca string) *config.Config {
		return config.New(&config.Options{
			CA:            ca,
			GlobalOptions: config.GlobalOptions{OutboundHttpsProxy: nullable.From(proxy.URL)},
		})
	}

	src := config.NewStaticSource(configWithCA(""))
	// The clone is taken before the config changes.
	transport := config.NewHTTPTransport(src).Clone()
	t.Cleanup(transport.CloseIdleConnections)
	get := func() error {
		transport.CloseIdleConnections()
		return getOrigin(t, transport, origin, "example.com")
	}

	var unknownAuthority x509.UnknownAuthorityError
	assert.ErrorAs(t, get(), &unknownAuthority, "without the CA")
	src.SetConfig(t.Context(), configWithCA(ca))
	assert.NoError(t, get(), "with the CA")
	src.SetConfig(t.Context(), configWithCA(""))
	assert.ErrorAs(t, get(), &unknownAuthority, "after the CA is removed")
	assert.Equal(t, 3, proxy.Connects("example.com"))
}

// newTLSOrigin starts a TLS server with a certificate valid for example.com,
// and returns it with that certificate encoded for [config.Options.CA].
func newTLSOrigin(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.Close)
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.Certificate().Raw,
	}))
	return s, ca
}

// dialTo returns a dial function that connects to s whatever the address.
func dialTo(s *httptest.Server) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, s.Listener.Addr().String())
	}
}

// getOrigin requests https://host on the port of origin.
func getOrigin(t *testing.T, transport http.RoundTripper, origin *httptest.Server, host string) error {
	t.Helper()
	_, port, err := net.SplitHostPort(origin.Listener.Addr().String())
	require.NoError(t, err)
	res, err := (&http.Client{Transport: transport}).Get("https://" + net.JoinHostPort(host, port))
	if err == nil {
		res.Body.Close()
	}
	return err
}

// connectProxy is an HTTP CONNECT proxy that records the authority of every
// CONNECT request it receives.
type connectProxy struct {
	*httptest.Server

	mu      sync.Mutex
	targets []string
	tunnels []net.Conn
}

func newConnectProxy(t *testing.T, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *connectProxy {
	t.Helper()
	p := &connectProxy{}
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
		go io.Copy(upstream, brw)
		io.Copy(client, upstream)
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
func (p *connectProxy) Connects(prefix string) int {
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
