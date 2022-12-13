package oidc

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
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/identity/oauth"
)

func TestRevoke(t *testing.T) {
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
				"issuer": baseURL.String(),
				"revocation_endpoint": baseURL.ResolveReference(&url.URL{
					Path: "/revoke",
				}).String(),
			})
		case "/revoke":
			assert.Equal(t, "ACCESS_TOKEN", r.FormValue("token"))
			assert.Equal(t, "access_token", r.FormValue("token_type_hint"))
			assert.Equal(t, "CLIENT_ID", r.FormValue("client_id"))
			assert.Equal(t, "CLIENT_SECRET", r.FormValue("client_secret"))

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

	assert.NoError(t, p.Revoke(ctx, &oauth2.Token{
		AccessToken: "ACCESS_TOKEN",
	}))
}
