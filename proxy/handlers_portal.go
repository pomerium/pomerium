package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/mcp"
	"github.com/pomerium/pomerium/pkg/endpoints"
	"github.com/pomerium/pomerium/pkg/telemetry/requestid"
	"github.com/pomerium/pomerium/proxy/portal"
	"github.com/pomerium/pomerium/ui"
)

func (p *Proxy) routesPortalHTML(w http.ResponseWriter, r *http.Request) error {
	u := p.getUserInfoData(r)
	rs, mcpStatusError := p.getPortalRoutes(r.Context(), u)
	m := u.ToJSON()
	m["routes"] = rs
	if mcpStatusError != "" {
		m["mcp_status_error"] = mcpStatusError
	}
	return ui.ServePage(w, r, "Routes", "Routes Portal", m)
}

func (p *Proxy) routesPortalJSON(w http.ResponseWriter, r *http.Request) error {
	u := p.getUserInfoData(r)
	rs, mcpStatusError := p.getPortalRoutes(r.Context(), u)
	m := map[string]any{}
	m["routes"] = rs
	if mcpStatusError != "" {
		m["mcp_status_error"] = mcpStatusError
	}

	b, err := json.Marshal(m)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
	return nil
}

func (p *Proxy) getPortalRoutes(ctx context.Context, u handlers.UserInfoData) ([]portal.Route, string) {
	options := p.currentConfig.Load().Options
	pu := p.getPortalUser(u)
	var routes []*config.Policy
	for route := range options.GetAllPolicies() {
		if portal.CheckRouteAccess(pu, route) {
			routes = append(routes, route)
		}
	}
	portalRoutes := portal.RoutesFromConfigRoutes(routes)

	var wg sync.WaitGroup
	for i, pr := range portalRoutes {
		wg.Go(func() {
			r := routes[i]
			for _, to := range r.To {
				if pr.LogoURL == "" {
					var err error
					pr.LogoURL, err = p.logoProvider.GetLogoURL(ctx, pr.From, to.URL.String())
					if err != nil && !errors.Is(err, portal.ErrLogoNotFound) {
						log.Ctx(ctx).Error().
							Err(err).
							Str("from", pr.From).
							Str("to", to.URL.String()).
							Msg("error retrieving logo for route")
					}
				}
			}
			portalRoutes[i] = pr
		})
	}
	wg.Wait()

	// Overlay MCP connection status if the MCP runtime flag is enabled.
	var mcpStatusError string
	if options.IsRuntimeFlagSet(config.RuntimeFlagMCP) {
		mcpStatusError = p.fillMCPPortalRoutes(ctx, u, portalRoutes)
	}

	return portalRoutes, mcpStatusError
}

func (p *Proxy) fillMCPPortalRoutes(ctx context.Context, u handlers.UserInfoData, portalRoutes []portal.Route) string {
	mcpSrv := p.mcp.Load()
	if mcpSrv == nil {
		log.Ctx(ctx).Debug().Msg("portal: MCP handler not loaded, skipping MCP route info")
		return ""
	}

	reqID := requestid.FromContext(ctx)

	userID := u.Session.GetUserId()
	if userID == "" {
		log.Ctx(ctx).Error().Str("request-id", reqID).Msg("portal: no user ID in session, skipping MCP route info")
		return fmt.Sprintf("Unable to load MCP connection status. Ask your administrator to check logs for request ID: %s", reqID)
	}

	infos, err := mcpSrv.GetPortalInfoForUser(ctx, userID)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Str("request-id", reqID).Msg("portal: failed to get MCP info for user")
		return fmt.Sprintf("Unable to load MCP connection status. Ask your administrator to check logs for request ID: %s", reqID)
	}

	// Build a lookup by host for matching portal routes to MCP server info.
	infoByHost := make(map[string]mcp.PortalRouteInfo, len(infos))
	for _, info := range infos {
		infoByHost[info.Host] = info
	}

	for i := range portalRoutes {
		if portalRoutes[i].Type != portal.RouteTypeMCP {
			continue
		}

		fromURL, err := url.Parse(portalRoutes[i].From)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).
				Str("from", portalRoutes[i].From).
				Msg("portal: failed to parse MCP route From URL")
			continue
		}

		info, ok := infoByHost[fromURL.Hostname()]
		if !ok {
			log.Ctx(ctx).Debug().
				Str("host", fromURL.Hostname()).
				Msg("portal: no MCP info found for route host")
			continue
		}

		portalRoutes[i].MCPConnected = info.Connected
		redirectURL := (&url.URL{Scheme: fromURL.Scheme, Host: fromURL.Host, Path: endpoints.PathPomeriumRoutes}).String()
		connectURL := url.URL{
			Scheme:   fromURL.Scheme,
			Host:     fromURL.Host,
			Path:     endpoints.PathPomeriumMCPConnect,
			RawQuery: url.Values{"redirect_url": {redirectURL}}.Encode(),
		}
		portalRoutes[i].MCPConnectURL = connectURL.String()
	}
	return ""
}

func (p *Proxy) getPortalUser(u handlers.UserInfoData) portal.User {
	pu := portal.User{}
	pu.SessionID = u.Session.GetId()
	pu.UserID = u.User.GetId()
	pu.Email = u.User.GetEmail()
	for _, dg := range u.DirectoryGroups {
		if v := dg.ID; v != "" {
			pu.Groups = append(pu.Groups, dg.ID)
		}
		if v := dg.Name; v != "" {
			pu.Groups = append(pu.Groups, dg.Name)
		}
	}
	return pu
}
