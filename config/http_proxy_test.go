package config_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
)

func TestHTTPTransportThroughProxy(t *testing.T) {
	t.Parallel()

	origin, ca := newTLSOrigin(t)

	// get requests https://host through a new proxy that tunnels every
	// CONNECT to origin.
	get := func(t *testing.T, ca, host string) error {
		t.Helper()
		proxy := newConnectProxy(t, origin)
		transport := config.NewHTTPTransport(config.NewStaticSource(config.New(&config.Options{CA: ca})))
		transport.Proxy = proxy.ProxyFunc()
		t.Cleanup(transport.CloseIdleConnections)
		err := getOrigin(t, transport, origin, host)
		assert.Equal(t, 1, proxy.Connects(), "request goes through the proxy")
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
	t.Run("server addressed by ip", func(t *testing.T) {
		// the certificate is valid for 127.0.0.1, but through a proxy the
		// handshake does not expose the address to match it against
		assert.ErrorContains(t, get(t, ca, "127.0.0.1"), "cannot verify a server addressed by IP through a proxy")
	})
}

func TestHTTPTransportThroughProxyFollowsCAChanges(t *testing.T) {
	t.Parallel()

	origin, ca := newTLSOrigin(t)
	proxy := newConnectProxy(t, origin)
	configWithCA := func(ca string) *config.Config {
		return config.New(&config.Options{CA: ca})
	}

	src := config.NewStaticSource(configWithCA(""))
	// The clone is taken before the config changes.
	transport := config.NewHTTPTransport(src).Clone()
	transport.Proxy = proxy.ProxyFunc()
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
	assert.Equal(t, 3, proxy.Connects())
}

// newTLSOrigin starts a TLS server with a certificate valid for example.com,
// and returns it with that certificate encoded for [config.Options.CA].
func newTLSOrigin(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(s.Close)
	ca := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: s.Certificate().Raw,
	}))
	return s, ca
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

// connectProxy is an HTTP CONNECT proxy that tunnels every CONNECT request to
// origin, whatever its authority, and counts them.
type connectProxy struct {
	*httptest.Server

	connects atomic.Int32
}

func newConnectProxy(t *testing.T, origin *httptest.Server) *connectProxy {
	t.Helper()
	p := &connectProxy{}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "only CONNECT is supported", http.StatusMethodNotAllowed)
			return
		}
		p.connects.Add(1)

		upstream, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", origin.Listener.Addr().String())
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
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
			return
		}
		go io.Copy(upstream, brw)
		io.Copy(client, upstream)
	}))
	t.Cleanup(p.Close)
	return p
}

// Connects returns the number of tunnels requested.
func (p *connectProxy) Connects() int {
	return int(p.connects.Load())
}

// ProxyFunc returns a [http.Transport.Proxy] function that selects p.
func (p *connectProxy) ProxyFunc() func(*http.Request) (*url.URL, error) {
	return func(*http.Request) (*url.URL, error) { return url.Parse(p.URL) }
}
