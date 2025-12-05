package handlers

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

type SessionInfoData struct {
	UserInfoData
	SessionData []SessionBindingData
}

type SessionBindingData struct {
	SessionBindingID         string
	Protocol                 string
	IssuedAt                 string
	ExpiresAt                string
	RevokeSessionBindingURL  string
	RevokeIdentityBindingURL string
	HasIdentityBinding       bool
}

func (data SessionInfoData) ToJSON() map[string]any {
	m := data.UserInfoData.ToJSON()
	m["sessionBindings"] = data.SessionData
	return m
}

func ServeSessionBindingInfo(data SessionInfoData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "SessionBindingInfo", "Session Bindings", data.ToJSON())
	})
}
