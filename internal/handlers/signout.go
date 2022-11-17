package handlers

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

// SignOutConfirmData is the data for the SignOutConfirm page.
type SignOutConfirmData struct {
	URL string
}

// ToJSON converts the data into a JSON map.
func (data SignOutConfirmData) ToJSON() map[string]interface{} {
	return map[string]interface{}{
		"url": data.URL,
	}
}

// SignOutConfirm returns a handler that renders the sign out confirm page.
func SignOutConfirm(data SignOutConfirmData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "SignOutConfirm", data.ToJSON())
	})
}
