package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWellKnownPomeriumHandler(t *testing.T) {
	t.Parallel()

	t.Run("cors", func(t *testing.T) {
		authenticateURL, _ := url.Parse("https://authenticate.example.com")
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.Header.Set("Origin", authenticateURL.String())
		r.Header.Set("Access-Control-Request-Method", "GET")
		WellKnownPomerium(authenticateURL).ServeHTTP(w, r)
		assert.Equal(t, http.StatusNoContent, w.Result().StatusCode)
	})
}
