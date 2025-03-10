// Package portal contains the code for the routes portal
package portal

import (
	"fmt"
	"strings"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/zero/importutil"
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
}

// RoutesFromConfigRoutes converts config routes into portal routes.
func RoutesFromConfigRoutes(routes []*config.Policy) []Route {
	prs := make([]Route, len(routes))
	for i, route := range routes {
		pr := Route{}
		pr.ID = route.ID
		if pr.ID == "" {
			pr.ID = fmt.Sprintf("%x", route.MustRouteID())
		}
		pr.Name = route.Name
		pr.From = route.From
		fromURL, err := urlutil.ParseAndValidateURL(route.From)
		if err == nil {
			if strings.HasPrefix(fromURL.Scheme, "tcp+") {
				pr.Type = "tcp"
				if len(fromURL.Path) > 1 {
					pr.ConnectCommand = "pomerium-cli tcp " + fromURL.String()
				} else {
					pr.ConnectCommand = "pomerium-cli tcp " + fromURL.Host
				}
			} else if strings.HasPrefix(fromURL.Scheme, "udp+") {
				pr.Type = "udp"
				pr.ConnectCommand = "pomerium-cli udp " + fromURL.Host
				if len(fromURL.Path) > 1 {
					pr.ConnectCommand = "pomerium-cli udp " + fromURL.String()
				} else {
					pr.ConnectCommand = "pomerium-cli udp " + fromURL.Host
				}
			} else {
				pr.Type = "http"
			}
		} else {
			pr.Type = "http"
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
