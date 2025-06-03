package oidc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestUserInfoRoundTrip(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `
            {
                "authorization_endpoint": "`+srv.URL+`/oauth2/authorize",
                "id_token_signing_alg_values_supported": [
                    "RS256"
                ],
                "issuer": "`+srv.URL+`",
                "jwks_uri": "`+srv.URL+`/.well-known/jwks.json",
                "response_types_supported": [
                    "code",
                    "token"
                ],
                "scopes_supported": [
                    "openid",
                    "email",
                    "phone",
                    "profile"
                ],
                "subject_types_supported": [
                    "public"
                ],
                "token_endpoint": "`+srv.URL+`/oauth2/token",
                "token_endpoint_auth_methods_supported": [
                    "client_secret_basic",
                    "client_secret_post"
                ],
                "userinfo_endpoint": "`+srv.URL+`/oauth2/userInfo"
            }`)
		case "/oauth2/userInfo":
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{ "email_verified": "true", "mail": "test@example.com" }`)
		}
	}))
	defer srv.Close()

	provider, err := oidc.NewProvider(t.Context(), srv.URL)
	if !assert.NoError(t, err) {
		return
	}

	token := oauth2.StaticTokenSource(&oauth2.Token{
		AccessToken:  "access-token",
		TokenType:    "Bearer",
		RefreshToken: "refresh-token",
		Expiry:       time.Now().Add(time.Minute),
	})

	userInfo, err := getUserInfo(t.Context(), provider, token)
	if !assert.NoError(t, err) {
		return
	}
	assert.True(t, userInfo.EmailVerified)
	assert.Equal(t, "test@example.com", userInfo.Email)
}
