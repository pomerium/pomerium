package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/proxy/portal"
)

func TestProxy_routesPortalJSON(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	cfg := config.New(config.NewDefaultOptions())
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

func TestApplyMCPPortalInfo(t *testing.T) {
	t.Parallel()

	portalRoutes := []portal.Route{
		{Type: portal.RouteTypeMCP, From: "https://mcp.example.com"},
		{Type: portal.RouteTypeMCP, From: "https://unknown.example.com"},
		{Type: portal.RouteTypeHTTP, From: "https://http.example.com"},
	}
	infos := []mcp.PortalRouteInfo{
		{
			Host:                  "mcp.example.com",
			ServerURL:             "https://mcp.example.com",
			Connected:             true,
			TokenExpiresAt:        "2026-09-21T10:00:00Z",
			RefreshTokenAvailable: true,
		},
	}

	applyMCPPortalInfo(t.Context(), portalRoutes, infos)

	assert.True(t, portalRoutes[0].MCPConnected)
	assert.Equal(t, "2026-09-21T10:00:00Z", portalRoutes[0].MCPTokenExpiresAt)
	assert.True(t, portalRoutes[0].MCPRefreshTokenAvailable)
	assert.Equal(t,
		"https://mcp.example.com/.pomerium/mcp/connect?redirect_url=https%3A%2F%2Fmcp.example.com%2F.pomerium%2Froutes",
		portalRoutes[0].MCPConnectURL)

	// routes with no matching MCP info, and non-MCP routes, are left untouched.
	assert.False(t, portalRoutes[1].MCPConnected)
	assert.Empty(t, portalRoutes[1].MCPConnectURL)
	assert.False(t, portalRoutes[2].MCPConnected)
	assert.Empty(t, portalRoutes[2].MCPTokenExpiresAt)
}
