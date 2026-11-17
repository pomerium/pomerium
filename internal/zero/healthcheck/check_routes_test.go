package healthcheck

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
)

func TestGetPingHTTPClient(t *testing.T) {
	original := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = original })
	pinned := config.NewHTTPTransport(config.NewStaticSource(config.New(config.NewDefaultOptions())))
	pinned.Proxy = func(*http.Request) (*url.URL, error) { return nil, errors.New("proxy used") }
	http.DefaultTransport = pinned

	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.Close)

	client := getPingHTTPClient()
	defer client.CloseIdleConnections()
	assert.Equal(t, connectionTimeout, client.Timeout)

	transport := client.Transport.(*http.Transport)
	assert.NotZero(t, transport.IdleConnTimeout)
	assert.NotZero(t, transport.MaxIdleConns)
	assert.NotZero(t, transport.TLSHandshakeTimeout)

	res, err := client.Get(s.URL)
	require.NoError(t, err)
	_ = res.Body.Close()
	assert.Equal(t, http.StatusOK, res.StatusCode)
}
