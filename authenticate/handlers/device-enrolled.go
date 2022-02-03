package handlers

import (
	"net/http"
	"net/url"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/ui"
)

// DeviceEnrolled displays an HTML page informing the user that they've successfully enrolled a device.
func DeviceEnrolled(authenticateURL *url.URL, sharedKey []byte) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "DeviceEnrolled", map[string]interface{}{
			"signOutUrl": urlutil.SignOutURL(r, authenticateURL, sharedKey),
		})
	})
}
