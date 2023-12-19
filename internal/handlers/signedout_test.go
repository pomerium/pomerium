package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/handlers"
)

func TestSignedOut(t *testing.T) {
	t.Parallel()

	t.Run("ok", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/.pomerium/signed_out", nil)

		handlers.SignedOut(handlers.SignedOutData{}).ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("redirect", func(t *testing.T) {
		t.Parallel()

		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/.pomerium/signed_out", nil)
		r.AddCookie(&http.Cookie{
			Name:  "_pomerium_signed_out_redirect_uri",
			Value: "https://www.google.com",
		})

		handlers.SignedOut(handlers.SignedOutData{}).ServeHTTP(w, r)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://www.google.com", w.Header().Get("Location"))
	})
}
