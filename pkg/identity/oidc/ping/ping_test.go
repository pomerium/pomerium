package ping_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc/ping"
)

func TestDeviceAuth(t *testing.T) {
	t.Parallel()

	var srv *httptest.Server

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&oidc.ProviderConfig{
			IssuerURL:     srv.URL,
			DeviceAuthURL: srv.URL + "/authorize/device",
		})
	})
	mux.HandleFunc("POST /authorize/device", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "CLIENT_ID", r.FormValue("client_id"), "should pass client_id")
		assert.Equal(t, "CLIENT_SECRET", r.FormValue("client_secret"), "should pass client_secret")
		assert.Equal(t, "openid profile email offline_access", r.FormValue("scope"), "should pass scope")

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(&oauth2.DeviceAuthResponse{
			DeviceCode: "DEVICE_CODE",
		})
	})

	srv = httptest.NewServer(mux)

	p, err := ping.New(t.Context(), &oauth.Options{
		ProviderName: "ping",
		ProviderURL:  srv.URL,
		RedirectURL:  mustParseURL(srv.URL),
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
	})
	require.NoError(t, err)

	res, err := p.DeviceAuth(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "DEVICE_CODE", res.DeviceCode)
}

func mustParseURL(rawURL string) *url.URL {
	u, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return u
}
