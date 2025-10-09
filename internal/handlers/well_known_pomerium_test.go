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
		r.Header.Set("Access-Control-Request-Method", http.MethodGet)
		WellKnownPomerium(authenticateURL).ServeHTTP(w, r)
		assert.Equal(t, http.StatusNoContent, w.Result().StatusCode)
	})
	t.Run("links", func(t *testing.T) {
		authenticateURL, _ := url.Parse("https://authenticate.example.com")
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://route.example.com", nil)
		WellKnownPomerium(authenticateURL).ServeHTTP(w, r)
		assert.JSONEq(t, `{
			"issuer": "https://route.example.com/",
			"authentication_callback_endpoint": "https://authenticate.example.com/oauth2/callback",
			"frontchannel_logout_uri": "https://route.example.com/.pomerium/sign_out",
			"jwks_uri": "https://route.example.com/.well-known/pomerium/jwks.json"
		}`, w.Body.String())
	})
}
