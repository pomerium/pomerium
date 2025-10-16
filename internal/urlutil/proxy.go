package urlutil

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/pomerium/pomerium/pkg/endpoints"
)

// ErrMissingRedirectURI indicates the pomerium_redirect_uri was missing from the query string.
var ErrMissingRedirectURI = errors.New("missing " + QueryRedirectURI)

// GetCallbackURL gets the proxy's callback URL from a request and a base64url encoded + encrypted session state JWT.
func GetCallbackURL(r *http.Request, encodedSessionJWT string, additionalHosts []string) (*url.URL, error) {
	rawRedirectURI := r.FormValue(QueryRedirectURI)
	if rawRedirectURI == "" {
		return nil, ErrMissingRedirectURI
	}

	redirectURI, err := ParseAndValidateURL(rawRedirectURI)
	if err != nil {
		return nil, err
	}

	var callbackURI *url.URL
	if callbackStr := r.FormValue(QueryCallbackURI); callbackStr != "" {
		callbackURI, err = ParseAndValidateURL(callbackStr)
		if err != nil {
			return nil, err
		}
	} else {
		// otherwise, assume callback is the same host as redirect
		callbackURI, err = DeepCopy(redirectURI)
		if err != nil {
			return nil, err
		}
		callbackURI.Path = endpoints.PathPomeriumCallback + "/"
		callbackURI.RawQuery = ""
	}

	callbackParams := callbackURI.Query()

	if r.FormValue(QueryIsProgrammatic) == "true" {
		callbackParams.Set(QueryIsProgrammatic, "true")
	}
	// propagate trace context
	if tracecontext := r.FormValue(QueryTraceparent); tracecontext != "" {
		callbackParams.Set(QueryTraceparent, tracecontext)
	}
	if tracestate := r.FormValue(QueryTracestate); tracestate != "" {
		callbackParams.Set(QueryTracestate, tracestate)
	}

	if len(additionalHosts) > 0 {
		callbackParams.Set(QueryAdditionalHosts, strings.Join(additionalHosts, ","))
	}

	// add our encoded and encrypted route-session JWT to a query param
	callbackParams.Set(QuerySessionEncrypted, encodedSessionJWT)
	callbackParams.Set(QueryRedirectURI, redirectURI.String())
	callbackURI.RawQuery = callbackParams.Encode()

	return callbackURI, nil
}
