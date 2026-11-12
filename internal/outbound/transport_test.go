package outbound_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/outbound"
	"github.com/pomerium/pomerium/internal/outbound/outboundtest"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func TestTransportThroughProxy(t *testing.T) {
	t.Parallel()

	origin, ca := newTLSOrigin(t, false)

	// get requests https://host through a new proxy that tunnels every
	// CONNECT to origin.
	get := func(t *testing.T, ca *x509.CertPool, host string) error {
		t.Helper()
		proxy := outboundtest.NewConnectProxy(t, dialTo(origin))
		o := outbound.New()
		o.Update(t.Context(), httpsProxy(ca, proxy.URL))
		transport := o.Transport()
		t.Cleanup(transport.CloseIdleConnections)
		err := getOrigin(t, transport, origin, host)
		assert.Equal(t, 1, proxy.Connects(host), "request goes through the proxy")
		return err
	}

	t.Run("trusted certificate authority", func(t *testing.T) {
		assert.NoError(t, get(t, ca, "example.com"))
	})
	t.Run("untrusted certificate authority", func(t *testing.T) {
		err := get(t, nil, "example.com")
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

func TestTransportThroughProxyFollowsCAChanges(t *testing.T) {
	t.Parallel()

	origin, ca := newTLSOrigin(t, false)
	proxy := outboundtest.NewConnectProxy(t, dialTo(origin))

	o := outbound.New()
	o.Update(t.Context(), httpsProxy(nil, proxy.URL))
	// The clone is taken before the settings change.
	transport := o.Transport().Clone()
	t.Cleanup(transport.CloseIdleConnections)
	get := func() error {
		transport.CloseIdleConnections()
		return getOrigin(t, transport, origin, "example.com")
	}

	var unknownAuthority x509.UnknownAuthorityError
	assert.ErrorAs(t, get(), &unknownAuthority, "without the CA")
	o.Update(t.Context(), httpsProxy(ca, proxy.URL))
	assert.NoError(t, get(), "with the CA")
	o.Update(t.Context(), httpsProxy(nil, proxy.URL))
	assert.ErrorAs(t, get(), &unknownAuthority, "after the CA is removed")
	assert.Equal(t, 3, proxy.Connects("example.com"))
}

// TestTransportInvalidProxy asserts that, with an invalid
// outbound_https_proxy, requests fail with an error that names the option and
// not the value, and that after a valid value they go through the proxy.
func TestTransportInvalidProxy(t *testing.T) {
	t.Parallel()

	origin, ca := newTLSOrigin(t, false)
	proxy := outboundtest.NewConnectProxy(t, dialTo(origin))
	o := outbound.New()
	o.Update(t.Context(), httpsProxy(ca, "http://user:s%ZZecret@invalid-proxy.example:3128"))
	transport := o.Transport()
	t.Cleanup(transport.CloseIdleConnections)

	err := getOrigin(t, transport, origin, "example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "outbound_https_proxy")
	for _, part := range []string{"user", "ecret", "invalid-proxy"} {
		assert.NotContains(t, err.Error(), part)
	}
	assert.Equal(t, 0, proxy.Connects("example.com"))

	o.Update(t.Context(), httpsProxy(ca, proxy.URL))
	assert.NoError(t, getOrigin(t, transport, origin, "example.com"))
	assert.Equal(t, 1, proxy.Connects("example.com"))
}

// TestTransportFollowsProxyChanges asserts that, after outbound_https_proxy
// changes, the next request to an origin that was already in use goes through
// the new proxy, for the transport and for a clone of it. Requests may fail
// while the connections to the previous proxy are closed.
func TestTransportFollowsProxyChanges(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		http2 bool
		proto int
		clone bool
	}{
		{"http1 origin", false, 1, false},
		{"http2 origin", true, 2, false},
		{"http1 origin clone", false, 1, true},
		{"http2 origin clone", true, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			origin, ca := newTLSOrigin(t, tc.http2)
			proxyA := outboundtest.NewConnectProxy(t, dialTo(origin))
			proxyB := outboundtest.NewConnectProxy(t, dialTo(origin))
			o := outbound.New()
			o.Update(t.Context(), httpsProxy(ca, proxyA.URL))
			transport := o.Transport()
			if tc.clone {
				transport = transport.Clone()
			}
			t.Cleanup(transport.CloseIdleConnections)
			client := &http.Client{Transport: transport}

			_, port, err := net.SplitHostPort(origin.Listener.Addr().String())
			require.NoError(t, err)
			get := func() error {
				res, err := client.Get("https://" + net.JoinHostPort("example.com", port))
				if err != nil {
					return err
				}
				_, _ = io.Copy(io.Discard, res.Body)
				res.Body.Close()
				assert.Equal(t, tc.proto, res.ProtoMajor)
				return nil
			}

			require.NoError(t, get())
			require.Equal(t, 1, proxyA.Connects("example.com"))

			o.Update(t.Context(), httpsProxy(ca, proxyB.URL))
			require.Eventually(t, func() bool { return get() == nil }, 10*time.Second, time.Millisecond)
			assert.Equal(t, 1, proxyB.Connects("example.com"), "the request goes through the new proxy")
			assert.Equal(t, 1, proxyA.Connects("example.com"), "the previous proxy gets no new tunnel")
		})
	}
}

// httpsProxy returns the settings with the CA pool ca and the
// outbound_https_proxy proxyURL.
func httpsProxy(ca *x509.CertPool, proxyURL string) outbound.Settings {
	s := outbound.ProxySettings(outbound.ProxyOptions{HTTPSProxy: nullable.From(proxyURL)})
	s.RootCAs = ca
	return s
}

// newTLSOrigin starts a TLS server with a certificate valid for example.com,
// with HTTP/2 enabled if http2 is set, and returns it with a CA pool that
// holds that certificate.
func newTLSOrigin(t *testing.T, http2 bool) (*httptest.Server, *x509.CertPool) {
	t.Helper()
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	s.EnableHTTP2 = http2
	s.StartTLS()
	t.Cleanup(s.Close)
	ca := x509.NewCertPool()
	ca.AddCert(s.Certificate())
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
