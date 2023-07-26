// Package webauthnutil contains types and functions for working with the webauthn package.
package webauthnutil

import (
	"net"
	"net/http"

	"golang.org/x/net/publicsuffix"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/webauthn"
)

// GetRelyingParty gets a RelyingParty for the given request and databroker client.
func GetRelyingParty(r *http.Request, client databroker.DataBrokerServiceClient) *webauthn.RelyingParty {
	return webauthn.NewRelyingParty(
		"https://"+GetEffectiveDomain(r),
		NewCredentialStorage(client),
	)
}

// GetEffectiveDomain returns the effective domain for an HTTP request.
func GetEffectiveDomain(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		h = r.Host
	}
	if tld, err := publicsuffix.EffectiveTLDPlusOne(h); err == nil {
		return tld
	}
	return h
}
