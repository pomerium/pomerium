package handlers

import (
	"net/http"
	"time"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

type SignInVerifyData struct {
	UserInfoData
	RedirectURL string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	SourceAddr  string
	Protocol    string
}

func (data SignInVerifyData) ToJSON() map[string]any {
	m := data.UserInfoData.ToJSON()
	m["redirectUrl"] = data.RedirectURL
	m["issuedAt"] = data.IssuedAt
	m["expiresAt"] = data.ExpiresAt
	m["sourceAddr"] = data.SourceAddr
	m["protocol"] = data.Protocol
	return m
}

func SignInVerify(data SignInVerifyData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "SignInVerify", "Verify Sign In", data.ToJSON())
	})
}
