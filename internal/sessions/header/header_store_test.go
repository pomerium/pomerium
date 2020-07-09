package header

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTokenFromHeader(t *testing.T) {
	t.Run("pomerium type", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "http://localhost/some/url", nil)
		r.Header.Set("Authorization", "Pomerium JWT")
		v := TokenFromHeader(r, "Authorization", "Pomerium")
		assert.Equal(t, "JWT", v)
	})
	t.Run("bearer type", func(t *testing.T) {
		r, _ := http.NewRequest("GET", "http://localhost/some/url", nil)
		r.Header.Set("Authorization", "Bearer Pomerium-JWT")
		v := TokenFromHeader(r, "Authorization", "Pomerium")
		assert.Equal(t, "JWT", v)
	})
}
