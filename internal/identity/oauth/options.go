// Package oauth provides support for making OAuth2 authorized and authenticated
// HTTP requests, as specified in RFC 6749. It can additionally grant
// authorization with Bearer JWT.
package oauth

import "net/url"

// Options contains the fields required for an OAuth 2.0 (inc. OIDC) auth flow.
//
// https://tools.ietf.org/html/rfc6749
// https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
type Options struct {
	ProviderName string

	// ProviderURL is the endpoint to look for .well-known/openid-configuration
	// OAuth2 related endpoints and will be autoconfigured based off this URL
	ProviderURL string

	// ClientID is the application's ID.
	ClientID string
	// ClientSecret is the application's secret.
	ClientSecret string
	// RedirectURL is the URL to redirect users going through
	// the OAuth flow, after the resource owner's URLs.
	RedirectURL *url.URL
	// Scope specifies optional requested permissions.
	Scopes []string

	// ServiceAccount can be set for those providers that require additional
	// credentials or tokens to do follow up API calls (e.g. Google)
	ServiceAccount string
}
