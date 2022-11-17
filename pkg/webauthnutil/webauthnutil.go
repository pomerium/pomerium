// Package webauthnutil contains types and functions for working with the webauthn package.
package webauthnutil

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/webauthn"
)

// GetRelyingParty gets a RelyingParty for the given request and databroker client.
func GetRelyingParty(r *http.Request, client databroker.DataBrokerServiceClient) *webauthn.RelyingParty {
	return webauthn.NewRelyingParty(urlutil.GetOrigin(r), NewCredentialStorage(client))
}
