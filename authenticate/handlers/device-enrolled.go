package handlers

import (
	"html/template"
	"net/http"

	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/httputil"
)

// DeviceEnrolled displays an HTML page informing the user that they've successfully enrolled a device.
func DeviceEnrolled() http.Handler {
	tpl := template.Must(frontend.NewTemplates())
	type TemplateData struct{}
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return tpl.ExecuteTemplate(w, "device-enrolled.html", TemplateData{})
	})
}
