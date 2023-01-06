package httputil

import (
	"crypto/tls"
	"net/http"
)

// GetInsecureTransport gets an insecure HTTP transport.
func GetInsecureTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return transport
}
