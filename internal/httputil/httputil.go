package httputil

import "net/http"

// StatusDeviceUnauthorized is the status code returned when a client's
// device credential is not authorized to access a page.
const StatusDeviceUnauthorized = 450

// StatusInvalidClientCertificate is the status code returned when a
// client's certificate is invalid. This is the same status code used
// by nginx for this purpose.
const StatusInvalidClientCertificate = 495

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
