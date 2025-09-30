package oidc_test

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

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
)

func TestDeviceAuthorization_UsesDiscoveryEndpoint_AndClientSecret(t *testing.T) {
	ctx, clear := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(clear)

	var srv *httptest.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			// Publish the device_authorization_endpoint
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":                        baseURL.String(),
				"device_authorization_endpoint": baseURL.ResolveReference(&url.URL{Path: "/auth/device"}).String(),
			})
		case "/auth/device":
			require.NoError(t, r.ParseForm())
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "CLIENT_ID", r.FormValue("client_id"))
			// ensure client_secret is sent for confidential clients
			assert.Equal(t, "CLIENT_SECRET", r.FormValue("client_secret"))
			// scope should include defaults
			assert.Contains(t, r.FormValue("scope"), "openid")

			json.NewEncoder(w).Encode(map[string]any{
				"device_code":               "DEV-CODE",
				"user_code":                 "USER-CODE",
				"verification_uri":          baseURL.ResolveReference(&url.URL{Path: "/verify"}).String(),
				"verification_uri_complete": baseURL.ResolveReference(&url.URL{Path: "/verify?user_code=USER-CODE"}).String(),
				"expires_in":                600,
			})
		default:
			t.Fatalf("unexpected url: %s", r.URL.Path)
		}
	})
	srv = httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	redirectURL, _ := url.Parse("https://localhost/oauth2/callback")
	p, err := oidc.New(ctx, &oauth.Options{
		ProviderURL:  srv.URL,
		RedirectURL:  redirectURL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
	})
	require.NoError(t, err)

	resp, err := p.DeviceAuth(ctx)
	require.NoError(t, err)
	assert.Equal(t, "DEV-CODE", resp.DeviceCode)
	assert.Equal(t, "USER-CODE", resp.UserCode)
}
