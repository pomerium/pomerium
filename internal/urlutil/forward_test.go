package urlutil

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetForwardAuthURL(t *testing.T) {
	t.Run("double-escaping", func(t *testing.T) {
		req, err := http.NewRequest("GET", "https://example.com", nil)
		require.NoError(t, err)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "protected-host.tld")
		req.Header.Set("X-Forwarded-Uri", "/example?a=b&c=d")

		u := GetForwardAuthURL(req)
		assert.Equal(t, "https://protected-host.tld/example?a=b&c=d", u.String())
	})
}
