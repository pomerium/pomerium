package authenticateflow

import (
	"net/http"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/urlutil"
)

type signatureVerifier struct {
	options   *config.Options
	sharedKey []byte
}

// VerifyAuthenticateSignature checks that the provided request has a valid
// signature (for the authenticate service).
func (v signatureVerifier) VerifyAuthenticateSignature(r *http.Request) error {
	return middleware.ValidateRequestURL(GetExternalAuthenticateRequest(r, v.options), v.sharedKey)
}

// GetExternalAuthenticateRequest canonicalizes an authenticate request URL
// based on the provided configuration options.
func GetExternalAuthenticateRequest(r *http.Request, options *config.Options) *http.Request {
	externalURL, err := options.GetAuthenticateURL()
	if err != nil {
		return r
	}

	internalURL, err := options.GetInternalAuthenticateURL()
	if err != nil {
		return r
	}

	return urlutil.GetExternalRequest(internalURL, externalURL, r)
}
