package httputil

// StatusInvalidClientCertificate is the status code returned when a
// client's certificate is invalid. This is the same status code used
// by nginx for this purpose.
const StatusInvalidClientCertificate = 495

var statusText = map[int]string{
	StatusInvalidClientCertificate: "a valid client certificate is required to access this page",
}

// StatusText returns a text for the HTTP status code. It returns the empty
// string if the code is unknown.
func StatusText(code int) string {
	return statusText[code]
}
