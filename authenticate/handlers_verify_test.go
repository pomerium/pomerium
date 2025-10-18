package authenticate_test

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/config"
)

func TestVerifyAccessToken(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "error", http.StatusInternalServerError)
	}))

	a, err := authenticate.New(t.Context(), &config.Config{
		Options: &config.Options{
			CookieSecret:          base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
			SharedKey:             base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x01}, 32)),
			AuthenticateURLString: "https://authenticate.example.com",

			Provider:    "oidc",
			ProviderURL: srv.URL,
		},
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://authenticate.example.com/.pomerium/verify-access-token",
		strings.NewReader(`{"accessToken":"ACCESS TOKEN"}`))
	require.NoError(t, err)

	a.Handler().ServeHTTP(w, r)

	assert.Equal(t, 200, w.Code)
	assert.JSONEq(t, `{"valid":false}`, w.Body.String())
}
