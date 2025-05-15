package github_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oauth/github"
)

func TestVerifyAccessToken(t *testing.T) {
	t.Parallel()

	ctx := testutil.GetContext(t, time.Minute)

	var srv *httptest.Server
	m := http.NewServeMux()
	m.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "token ACCESS_TOKEN", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode(map[string]any{
			"id":    1234,
			"login": "LOGIN",
			"name":  "NAME",
		})
	})
	m.HandleFunc("GET /user/emails", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "token ACCESS_TOKEN", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode([]map[string]any{{
			"email":      "EMAIL",
			"verified":   true,
			"primary":    true,
			"visibility": "public",
		}})
	})
	srv = httptest.NewServer(m)

	p, err := github.New(ctx, &oauth.Options{
		ProviderURL:  srv.URL,
		ClientID:     "CLIENT_ID",
		ClientSecret: "CLIENT_SECRET",
		RedirectURL:  urlutil.MustParseAndValidateURL("https://www.example.com"),
	})
	require.NoError(t, err)

	claims, err := p.VerifyAccessToken(ctx, "ACCESS_TOKEN")
	require.NoError(t, err)
	delete(claims, "exp")
	delete(claims, "iat")
	delete(claims, "nbf")
	assert.Equal(t, map[string]any{
		"email":          "EMAIL",
		"email_verified": true,
		"name":           "NAME",
		"sub":            "LOGIN",
		"user":           "LOGIN",
	}, claims)
}
