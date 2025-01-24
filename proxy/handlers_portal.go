package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/proxy/portal"
)

func (p *Proxy) routesPortalJSON(w http.ResponseWriter, r *http.Request) error {
	u := p.getUserInfoData(r)
	rs := p.getPortalRoutes(u)
	m := map[string]any{}
	m["routes"] = rs

	b, err := json.Marshal(m)
	if err != nil {
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
	return nil
}

func (p *Proxy) getPortalRoutes(u handlers.UserInfoData) []portal.Route {
	options := p.currentOptions.Load()
	pu := p.getPortalUser(u)
	var routes []*config.Policy
	for route := range options.GetAllPolicies() {
		if portal.CheckRouteAccess(pu, route) {
			routes = append(routes, route)
		}
	}
	return portal.RoutesFromConfigRoutes(routes)
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
