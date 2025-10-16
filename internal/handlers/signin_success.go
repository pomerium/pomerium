package handlers

import (
	"net/http"
	"time"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

type SignInSuccessData struct {
	UserInfoData
	Protocol  string
	ExpiresAt *time.Time
}

func (data SignInSuccessData) ToJSON() map[string]any {
	m := data.UserInfoData.ToJSON()
	if data.ExpiresAt != nil {
		m["expiresAt"] = data.ExpiresAt.Format(time.RFC1123)
	} else {
		m["expiresAt"] = "Until revoked"
	}
	m["protocol"] = data.Protocol
	return m
}

func SignInSuccess(data SignInSuccessData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "SignInSuccess", "Sign In Successful", data.ToJSON())
	})
}
