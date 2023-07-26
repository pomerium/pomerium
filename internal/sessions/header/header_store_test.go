package header

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenFromHeader(t *testing.T) {
	t.Run("pomerium header", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "http://localhost/some/url", nil)
		r.Header.Set("X-Pomerium-Authorization", "JWT")
		v := TokenFromHeaders(r)
		assert.Equal(t, "JWT", v)
	})
	t.Run("pomerium type", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "http://localhost/some/url", nil)
		r.Header.Set("Authorization", "Pomerium JWT")
		v := TokenFromHeaders(r)
		assert.Equal(t, "JWT", v)
	})
	t.Run("bearer type", func(t *testing.T) {
		r, _ := http.NewRequest(http.MethodGet, "http://localhost/some/url", nil)
		r.Header.Set("Authorization", "Bearer Pomerium-JWT")
		v := TokenFromHeaders(r)
		assert.Equal(t, "JWT", v)
	})
	t.Run("basic auth", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "http://localhost/some/url", nil)
		r.SetBasicAuth("pomerium", "JWT")
		v := TokenFromHeaders(r)
		assert.Equal(t, "JWT", v)
	})
}
