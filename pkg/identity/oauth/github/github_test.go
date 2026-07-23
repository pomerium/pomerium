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
			"avatar_url": "https://avatars.example.com/u1234.png",
			"blog":       "https://blog.example.com",
			"html_url":   "https://users.example.com/u1234",
			"id":         1234,
			"login":      "LOGIN",
			"name":       "NAME",
			"node_id":    "u1234",
		})
	})
	m.HandleFunc("GET /user/emails", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "token ACCESS_TOKEN", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		json.NewEncoder(w).Encode([]map[string]any{{
			"email":      "EMAIL",
			"primary":    true,
			"verified":   true,
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
		"email_verified":     true,
		"email":              "EMAIL",
		"name":               "NAME",
		"picture":            "https://avatars.example.com/u1234.png",
		"preferred_username": "LOGIN",
		"profile":            "https://users.example.com/u1234",
		"sub":                "u1234",
		"user":               "LOGIN",
		"website":            "https://blog.example.com",
	}, claims)
}
