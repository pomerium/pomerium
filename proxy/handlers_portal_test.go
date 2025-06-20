package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
)

func TestProxy_routesPortalJSON(t *testing.T) {
	ctx := t.Context()
	cfg := &config.Config{Options: config.NewDefaultOptions()}
	to, err := config.ParseWeightedUrls("https://to.example.com")
	require.NoError(t, err)
	cfg.Options.Routes = append(cfg.Options.Routes, config.Policy{
		Name:                             "public",
		Description:                      "PUBLIC ROUTE",
		LogoURL:                          "https://logo.example.com",
		From:                             "https://from.example.com",
		To:                               to,
		AllowPublicUnauthenticatedAccess: true,
	})
	proxy, err := New(ctx, cfg)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodGet, "/.pomerium/api/v1/routes", nil)
	w := httptest.NewRecorder()

	router := httputil.NewRouter()
	router = proxy.registerDashboardHandlers(router, cfg.Options)
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	assert.JSONEq(t, `{"routes":[
		{
			"id": "1013c6be524d7fbd",
			"name": "public",
			"from": "https://from.example.com",
			"type": "http",
			"description": "PUBLIC ROUTE",
			"logo_url": "https://logo.example.com"
		}
	]}`, w.Body.String())
}
