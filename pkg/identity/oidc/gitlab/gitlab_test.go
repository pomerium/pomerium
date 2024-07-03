package gitlab_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc/gitlab"
)

func TestGetOptions(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"https://gitlab.com",
		gitlab.GetOptions(&oauth.Options{}).ProviderURL,
		"should set default provider url")
	assert.Equal(t,
		[]string{"openid", "profile", "email"},
		gitlab.GetOptions(&oauth.Options{}).Scopes,
		"should set default scopes")
	assert.Equal(t,
		"https://gitlab.com",
		gitlab.GetOptions(&oauth.Options{ProviderURL: "https://gitlab.com/"}).ProviderURL,
		"should trim trailing slash")
}

func TestTrimsSlash(t *testing.T) {
	t.Parallel()

	srv := startMockServer(t)

	ctx := context.Background()
	options := &oauth.Options{
		ProviderName: gitlab.Name,
		ProviderURL:  srv.URL + "/",
	}
	provider, err := gitlab.New(ctx, options)
	assert.NoError(t, err)
	_, err = provider.GetProvider()
	assert.NoError(t, err)
}

func startMockServer(t *testing.T) *httptest.Server {
	t.Helper()

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		baseURL, err := url.Parse(srv.URL)
		require.NoError(t, err)

		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 baseURL.String(),
				"authorization_endpoint": srv.URL + "/authorize",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}
