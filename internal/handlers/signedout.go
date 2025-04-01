package handlers

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

// SignedOutData is the data for the SignedOut page.
type SignedOutData struct {
	BrandingOptions httputil.BrandingOptions
}

// ToJSON converts the data into a JSON map.
func (data SignedOutData) ToJSON() map[string]any {
	m := map[string]any{}
	httputil.AddBrandingOptionsToMap(m, data.BrandingOptions)
	return m
}

// SignedOut returns a handler that renders the signed out page.
func SignedOut(data SignedOutData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		if redirectURI, ok := httputil.GetSignedOutRedirectURICookie(w, r); ok {
			httputil.Redirect(w, r, redirectURI, http.StatusFound)
			return nil
		}

		// otherwise show the signed-out page
		return ui.ServePage(w, r, http.StatusOK, "SignedOut", "Signed Out", data.ToJSON())
	})
}
