package outbound

import (
	"net"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/http/httpproxy"

	"github.com/pomerium/pomerium/internal/outbound/outboundtest"
	"github.com/pomerium/pomerium/pkg/nullable"
)

func withProxy(proxyURL string) Settings {
	return Settings{Proxy: httpproxy.Config{HTTPProxy: proxyURL}}
}

func trackedConns(o *HTTP) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.conns)
}

func TestHTTPTracksOpenConnections(t *testing.T) {
	t.Parallel()

	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(s.Close)

	o := New()
	transport := o.Transport().Clone()
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	for range 3 {
		res, err := client.Get(s.URL)
		require.NoError(t, err)
		res.Body.Close()
	}
	assert.Equal(t, 1, trackedConns(o), "the pooled connection is tracked")

	transport.CloseIdleConnections()
	assert.Equal(t, 0, trackedConns(o), "a closed connection is not tracked")

	res, err := client.Get(s.URL)
	require.NoError(t, err)
	res.Body.Close()
	o.Update(t.Context(), withProxy("http://proxy.example:3128"))
	assert.Equal(t, 0, trackedConns(o), "connections are not tracked after the proxy settings change")
}

func TestHTTPKeepsConnectionsWhenProxySettingsAreUnchanged(t *testing.T) {
	t.Parallel()

	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(s.Close)

	o := New()
	o.Update(t.Context(), withProxy("http://proxy.example:3128"))
	conn, err := o.dial(t.Context(), "tcp", s.Listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	o.Update(t.Context(), withProxy("http://proxy.example:3128"))
	assert.Equal(t, 1, trackedConns(o))
}

func TestHTTPDialRacingProxyChange(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	o := New()
	o.Update(t.Context(), withProxy("http://proxy-a.example:3128"))
	dialing := make(chan struct{})
	release := make(chan struct{})
	o.dialer.Control = func(string, string, syscall.RawConn) error {
		close(dialing)
		<-release
		return nil
	}

	errc := make(chan error, 1)
	go func() {
		conn, err := o.dial(t.Context(), "tcp", ln.Addr().String())
		if conn != nil {
			conn.Close()
		}
		errc <- err
	}()
	<-dialing
	o.Update(t.Context(), withProxy("http://proxy-b.example:3128"))
	close(release)

	assert.ErrorIs(t, <-errc, errProxyChanged)
	assert.Equal(t, 0, trackedConns(o))
}

// TestHTTPInvalidProxyOptionMatchingEnvironment asserts that an
// invalid outbound_http_proxy fails requests after settings whose environment
// HTTP_PROXY has the same value, which does not.
func TestHTTPInvalidProxyOptionMatchingEnvironment(t *testing.T) {
	outboundtest.ClearProxyEnv(t)
	const invalid = " http://proxy.example:3128"
	t.Setenv("HTTP_PROXY", invalid)
	req := httptest.NewRequest(http.MethodGet, "http://idp.example/token", nil)

	o := New()
	o.Update(t.Context(), ProxySettings(ProxyOptions{}))
	proxyURL, err := o.Proxy(req)
	assert.NoError(t, err)
	assert.Nil(t, proxyURL)

	o.Update(t.Context(), ProxySettings(ProxyOptions{HTTPProxy: nullable.From(invalid)}))
	_, err = o.Proxy(req)
	assert.ErrorContains(t, err, "outbound_http_proxy")
}
