package httputil_test

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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
