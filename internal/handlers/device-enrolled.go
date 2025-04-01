package handlers

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

// DeviceEnrolled displays an HTML page informing the user that they've successfully enrolled a device.
func DeviceEnrolled(data UserInfoData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, http.StatusOK, "DeviceEnrolled", "Device Enrolled", data.ToJSON())
	})
}
