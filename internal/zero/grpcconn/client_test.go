package grpcconn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		endpoint      string
		connectionURI string
		requireTLS    bool
		expectError   bool
	}{
		{"http://localhost:8721", "dns:localhost:8721", false, false},
		{"https://localhost:8721", "dns:localhost:8721", true, false},
		{"http://localhost:8721/", "dns:localhost:8721", false, false},
		{"https://localhost:8721/", "dns:localhost:8721", true, false},
		{"http://localhost", "dns:localhost:80", false, false},
		{"https://localhost", "dns:localhost:443", true, false},

		{endpoint: "", expectError: true},
		{endpoint: "http://", expectError: true},
		{endpoint: "https://", expectError: true},
		{endpoint: "localhost:8721", expectError: true},
		{endpoint: "http://localhost:8721/path", expectError: true},
		{endpoint: "https://localhost:8721/path", expectError: true},
	} {
		t.Run(tc.endpoint, func(t *testing.T) {
			t.Parallel()
			cfg, err := getConfig(tc.endpoint)
			if tc.expectError {
				require.Error(t, err)
				return
			}
			if assert.NoError(t, err) {
				assert.Equal(t, tc.connectionURI, cfg.GetConnectionURI(), "connection uri")
				assert.Equal(t, tc.requireTLS, cfg.RequireTLS(), "require tls")
			}
		})
	}
}
