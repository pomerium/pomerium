package httputil

import (
	"crypto/tls"
	"net/http"
)

// GetInsecureTransport returns an HTTP transport which skips TLS verification.
func GetInsecureTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Dial = nil
	transport.DialContext = nil
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
	}
	return transport
}
