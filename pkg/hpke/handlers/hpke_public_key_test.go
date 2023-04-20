package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/pkg/hpke"
	"github.com/pomerium/pomerium/pkg/hpke/handlers"
)

func TestHPKEPublicKeyHandler(t *testing.T) {
	t.Parallel()

	k1 := hpke.DerivePrivateKey([]byte("TEST"))

	t.Run("cors", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodOptions, "/", nil)
		r.Header.Set("Origin", "https://www.example.com")
		r.Header.Set("Access-Control-Request-Method", "GET")
		handlers.HPKEPublicKeyHandler(k1.PublicKey()).ServeHTTP(w, r)
		assert.Equal(t, http.StatusNoContent, w.Result().StatusCode)
	})
	t.Run("keys", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		handlers.HPKEPublicKeyHandler(k1.PublicKey()).ServeHTTP(w, r)

		assert.Equal(t, k1.PublicKey().Bytes(), w.Body.Bytes())
	})
}
