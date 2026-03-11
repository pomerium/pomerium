// Package portal contains the code for the routes portal
package portal

import (
	"strings"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/zero/importutil"
)

// Route type constants.
const (
	RouteTypeHTTP = "http"
	RouteTypeTCP  = "tcp"
	RouteTypeUDP  = "udp"
	RouteTypeMCP  = "mcp"
)

// A Route is a portal route.
type Route struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Type           string `json:"type"`
	From           string `json:"from"`
	Description    string `json:"description"`
	ConnectCommand string `json:"connect_command,omitempty"`
	LogoURL        string `json:"logo_url"`
	MCPConnectURL  string `json:"mcp_connect_url,omitempty"`
	MCPConnected   bool   `json:"mcp_connected,omitempty"`
}

// RoutesFromConfigRoutes converts config routes into portal routes.
func RoutesFromConfigRoutes(routes []*config.Policy) []Route {
	prs := make([]Route, len(routes))
	for i, route := range routes {
		pr := Route{}
		pr.ID = route.ID
		if pr.ID == "" {
			pr.ID = route.MustRouteID()
		}
		pr.Name = route.Name
		pr.From = route.From
		if route.IsMCPServer() {
			pr.Type = RouteTypeMCP
			if _, err := urlutil.ParseAndValidateURL(route.From); err != nil {
				log.Error().Err(err).Str("from", route.From).Msg("portal: invalid MCP route URL")
			}
		} else if fromURL, err := urlutil.ParseAndValidateURL(route.From); err == nil {
			if strings.HasPrefix(fromURL.Scheme, "tcp+") {
				pr.Type = RouteTypeTCP
				if len(fromURL.Path) > 1 {
					pr.ConnectCommand = "pomerium-cli tcp " + fromURL.String()
				} else {
					pr.ConnectCommand = "pomerium-cli tcp " + fromURL.Host
				}
			} else if strings.HasPrefix(fromURL.Scheme, "udp+") {
				pr.Type = RouteTypeUDP
				pr.ConnectCommand = "pomerium-cli udp " + fromURL.Host
				if len(fromURL.Path) > 1 {
					pr.ConnectCommand = "pomerium-cli udp " + fromURL.String()
				} else {
					pr.ConnectCommand = "pomerium-cli udp " + fromURL.Host
				}
			} else {
				pr.Type = RouteTypeHTTP
			}
		} else {
			pr.Type = RouteTypeHTTP
		}
		pr.Description = route.Description
		pr.LogoURL = route.LogoURL
		prs[i] = pr
	}
	// generate names if they're empty
	for i, name := range importutil.GenerateRouteNames(routes) {
		if prs[i].Name == "" {
			prs[i].Name = name
		}
	}
	return prs
}
