package httputil

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetClientIPAddress(t *testing.T) {
	t.Parallel()

	r1, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", GetClientIPAddress(r1))

	r2, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	r2.RemoteAddr = "127.0.0.2:1234"
	assert.Equal(t, "127.0.0.2", GetClientIPAddress(r2))

	r3, err := http.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(t, err)
	r3.RemoteAddr = "127.0.0.3:1234"
	r3.Header.Set("X-Envoy-External-Address", "127.0.0.3")
	assert.Equal(t, "127.0.0.3", GetClientIPAddress(r3))
}
