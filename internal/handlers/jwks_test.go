package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJWKSHandler(t *testing.T) {
	t.Parallel()

	t.Run("cors", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.Header.Set("Origin", "https://www.example.com")
		r.Header.Set("Access-Control-Request-Method", "GET")
		JWKSHandler("").ServeHTTP(w, r)
		assert.Equal(t, http.StatusNoContent, w.Result().StatusCode)
	})
}
