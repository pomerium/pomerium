package handlers

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

type SignInVerifyData struct {
	BrandingOptions httputil.BrandingOptions
	RedirectURL     string
}

func (data SignInVerifyData) ToJSON() map[string]any {
	m := map[string]any{}
	m["redirectUrl"] = data.RedirectURL
	httputil.AddBrandingOptionsToMap(m, data.BrandingOptions)
	return m
}

func SignInVerify(data SignInVerifyData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "SignInVerify", "Verify Sign In", data.ToJSON())
	})
}
