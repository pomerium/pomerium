package httputil_test

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/pires/go-proxyproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/httputil"
)

func TestNewLocalProxyProtocolTransport(t *testing.T) {
	t.Parallel()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = li.Close() })

	li = &proxyproto.Listener{
		Listener: li,
		ConnPolicy: func(_ proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
	}

	srv := &httptest.Server{
		Listener: li,
		Config: &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.Write([]byte("HELLO WORLD"))
			}),
		},
	}
	srv.Start()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	t1 := &http.Transport{}
	t2 := httputil.NewLocalProxyProtocolTransport(t1)

	_, err = (&http.Client{Transport: t1}).Do(req)
	assert.ErrorIs(t, err, io.EOF, "should close connections not using the proxy protocol")

	r2, err := (&http.Client{Transport: t2}).Do(req)
	assert.NoError(t, err)
	defer r2.Body.Close()

	bs, err := io.ReadAll(r2.Body)
	assert.NoError(t, err)
	assert.Equal(t, "HELLO WORLD", string(bs))
}

func TestNewLocalProxyProtocolTransport_TLSDialer(t *testing.T) {
	t.Parallel()

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	srv.Listener = &proxyproto.Listener{
		Listener: srv.Listener,
		ConnPolicy: func(_ proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			return proxyproto.REQUIRE, nil
		},
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	tlsConfig := srv.Client().Transport.(*http.Transport).TLSClientConfig
	base := &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&tls.Dialer{Config: tlsConfig}).DialContext(ctx, network, addr)
		},
		TLSClientConfig: tlsConfig,
	}
	transport := httputil.NewLocalProxyProtocolTransport(base)

	res, err := (&http.Client{Transport: transport}).Get(srv.URL)
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusNoContent, res.StatusCode)
}

func TestNewTransport(t *testing.T) {
	t.Parallel()

	def := http.DefaultTransport.(*http.Transport)
	transport := httputil.NewTransport(func(transport *http.Transport) {
		transport.MaxIdleConns = 1
		transport.Proxy = nil
	})

	assert.NotSame(t, def, transport)
	assert.Equal(t, 1, transport.MaxIdleConns)
	assert.Nil(t, transport.Proxy)
	assert.Equal(t, def.IdleConnTimeout, transport.IdleConnTimeout)
	assert.Equal(t, def.TLSHandshakeTimeout, transport.TLSHandshakeTimeout)
	assert.Equal(t, def.ExpectContinueTimeout, transport.ExpectContinueTimeout)
	assert.NotEqual(t, 1, def.MaxIdleConns, "http.DefaultTransport.MaxIdleConns")
	assert.NotNil(t, def.Proxy, "http.DefaultTransport.Proxy")
}

// TestSetTLSClientConfig covers every combination of the four dial hooks a
// transport can inherit.
func TestSetTLSClientConfig(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	rootCAs := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs

	const (
		hookDial = 1 << iota
		hookDialContext
		hookDialTLS
		hookDialTLSContext
		hookAll
	)
	for mask := range hookAll {
		name := fmt.Sprintf("Dial=%t,DialContext=%t,DialTLS=%t,DialTLSContext=%t",
			mask&hookDial != 0, mask&hookDialContext != 0, mask&hookDialTLS != 0, mask&hookDialTLSContext != 0)
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var plainDials, tlsDials atomic.Int32
			var d net.Dialer
			transport := &http.Transport{}
			if mask&hookDial != 0 {
				transport.Dial = func(network, addr string) (net.Conn, error) {
					plainDials.Add(1)
					return d.Dial(network, addr)
				}
			}
			if mask&hookDialContext != 0 {
				transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					plainDials.Add(1)
					return d.DialContext(ctx, network, addr)
				}
			}
			if mask&hookDialTLS != 0 {
				transport.DialTLS = func(_, _ string) (net.Conn, error) {
					tlsDials.Add(1)
					return nil, errors.New("inherited DialTLS")
				}
			}
			if mask&hookDialTLSContext != 0 {
				transport.DialTLSContext = func(_ context.Context, _, _ string) (net.Conn, error) {
					tlsDials.Add(1)
					return nil, errors.New("inherited DialTLSContext")
				}
			}

			httputil.SetTLSClientConfig(transport, &tls.Config{RootCAs: rootCAs})

			res, err := (&http.Client{Transport: transport}).Get(srv.URL)
			require.NoError(t, err)
			_ = res.Body.Close()
			assert.Equal(t, http.StatusNoContent, res.StatusCode)
			assert.Zero(t, tlsDials.Load(), "TLS dial hook calls")
			if mask&(hookDial|hookDialContext) != 0 {
				assert.Equal(t, int32(1), plainDials.Load(), "plain dial hook calls")
			}
		})
	}
}
