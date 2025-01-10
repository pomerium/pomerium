package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/pomerium/pomerium/internal/handlers"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/proxy/portal"
	"github.com/pomerium/pomerium/ui"
)

func (p *Proxy) routesPortalHTML(w http.ResponseWriter, r *http.Request) error {
	u := p.getUserInfoData(r)
	rs := p.getPortalRoutes(u)
	m := u.ToJSON()
	m["routes"] = rs
	return ui.ServePage(w, r, "Routes", "Routes Portal", m)
}

func (p *Proxy) routesPortalJSON(w http.ResponseWriter, r *http.Request) error {
	u := p.getUserInfoData(r)
	rs := p.getPortalRoutes(u)
	m := u.ToJSON()
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
	pu := p.getPortalUserInfo(u)
	var routes []portal.Route
	for route := range options.GetAllPolicies() {
		if portal.CheckRouteAccess(pu, route) {
			routes = append(routes, portal.RouteFromConfigRoute(route))
		}
	}
	return routes
}

func (p *Proxy) getPortalUserInfo(u handlers.UserInfoData) portal.UserInfo {
	pu := portal.UserInfo{}
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
