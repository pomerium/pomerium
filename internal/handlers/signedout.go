package handlers

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

// SignedOutData is the data for the SignedOut page.
type SignedOutData struct{}

// ToJSON converts the data into a JSON map.
func (data SignedOutData) ToJSON() map[string]interface{} {
	return map[string]interface{}{}
}

// SignedOut returns a handler that renders the signed out page.
func SignedOut(data SignedOutData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "SignedOut", data.ToJSON())
	})
}
