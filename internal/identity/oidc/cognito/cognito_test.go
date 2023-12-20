package cognito

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/identity/oauth"
)

func TestProvider(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	t.Cleanup(clearTimeout)

	var srv *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 baseURL.String(),
				"authorization_endpoint": srv.URL + "/authorize",
			})

		default:
			assert.Failf(t, "unexpected http request", "url: %s", r.URL.String())
		}
	})
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	redirectURL, err := url.Parse(srv.URL)
	require.NoError(t, err)

	p, err := New(ctx, &oauth.Options{
		ProviderURL:  srv.URL,
		RedirectURL:  redirectURL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
	})
	require.NoError(t, err)
	require.NotNil(t, p)

	t.Run("SignOut", func(t *testing.T) {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "https://authenticate.example.com/.pomerium/sign_out", nil)
		err := p.SignOut(w, r, "", "https://authenticate.example.com/.pomerium/signed_out", "https://www.example.com?a=b")
		assert.NoError(t, err)
		assert.Equal(t, srv.URL+"/logout?client_id=CLIENT_ID&logout_uri=https%3A%2F%2Fauthenticate.example.com%2F.pomerium%2Fsigned_out", w.Header().Get("Location"))
		assert.Equal(t, []*http.Cookie{{
			Name:     "_pomerium_signed_out_redirect_uri",
			Value:    "https://www.example.com?a=b",
			MaxAge:   300,
			Secure:   true,
			HttpOnly: true,
			Raw:      "_pomerium_signed_out_redirect_uri=https://www.example.com?a=b; Max-Age=300; HttpOnly; Secure",
		}}, w.Result().Cookies())
	})
}
