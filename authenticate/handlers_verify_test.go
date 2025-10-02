package authenticate_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/authenticate"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestVerifyAccessToken(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)
	a, err := authenticate.New(ctx, &config.Config{
		Options: &config.Options{
			CookieSecret:             cryptutil.NewBase64Key(),
			SharedKey:                cryptutil.NewBase64Key(),
			AuthenticateCallbackPath: "/oauth2/callback",
			AuthenticateURLString:    "https://authenticate.example.com",

			Provider:    "oidc",
			ProviderURL: "http://oidc.example.com",
		},
	})
	require.NoError(t, err)

	w := httptest.NewRecorder()
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://authenticate.example.com/.pomerium/verify-access-token",
		strings.NewReader(`{"accessToken":"ACCESS TOKEN"}`))
	require.NoError(t, err)

	a.ServeHTTP(w, r)

	assert.Equal(t, 200, w.Code)
	assert.JSONEq(t, `{"valid":false}`, w.Body.String())
}
