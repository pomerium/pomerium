package httputil

import (
	"net"
	"net/http"
)

const (
	// StatusDeviceUnauthorized is the status code returned when a client's
	// device credential is not authorized to access a page.
	StatusDeviceUnauthorized = 450
	// StatusInvalidClientCertificate is the status code returned when a
	// client's certificate is invalid. This is the same status code used
	// by nginx for this purpose.
	StatusInvalidClientCertificate = 495
)

var detailsText = map[int]string{
	StatusDeviceUnauthorized: "your device fails to meet the requirements necessary to access this page, please contact your administrator for assistance",
}

// DetailsText returns extra details for an HTTP status code. It returns StatusText if not found.
func DetailsText(code int) string {
	txt, ok := detailsText[code]
	if ok {
		return txt
	}

	return StatusText(code)
}

var statusText = map[int]string{
	StatusDeviceUnauthorized:       "device not authorized",
	StatusInvalidClientCertificate: "a valid client certificate is required to access this page",
}

// StatusText returns a text for the HTTP status code. It returns http.StatusText if not found.
func StatusText(code int) string {
	txt, ok := statusText[code]
	if ok {
		return txt
	}
	return http.StatusText(code)
}

// GetClientIPAddress gets a client's IP address for an HTTP request.
func GetClientIPAddress(r *http.Request) string {
	if ip := r.Header.Get("X-Envoy-External-Address"); ip != "" {
		return ip
	}

	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return ip
	}

	return "127.0.0.1"
}
