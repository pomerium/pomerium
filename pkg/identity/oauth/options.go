// Package oauth provides support for making OAuth2 authorized and authenticated
// HTTP requests, as specified in RFC 6749. It can additionally grant
// authorization with Bearer JWT.
package oauth

import (
	"net/url"
)

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

	// AuthCodeOptions specifies additional key value pairs query params to add
	// to the request flow signin url.
	AuthCodeOptions map[string]string

	// When set validates the audience in access tokens.
	AccessTokenAllowedAudiences *[]string

	// When set to true, any existing ID token will always be overwritten
	// (replaced or cleared) after a successful session refresh.
	OverwriteIDTokenOnRefresh bool
}
