package oauth21

import (
	"fmt"
	"net/url"
	"slices"

	"github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

func ValidateAuthorizationRequest(
	client *rfc7591v1.Metadata,
	req *gen.AuthorizationRequest,
) error {
	if err := ValidateAuthorizationRequestRedirectURI(client, req.RedirectUri); err != nil {
		return err
	}
	if err := ValidateAuthorizationRequestCodeChallenge(client, req); err != nil {
		return err
	}
	return nil
}

func ValidateAuthorizationRequestCodeChallenge(
	client *rfc7591v1.Metadata,
	req *gen.AuthorizationRequest,
) error {
	m := client.GetTokenEndpointAuthMethod()
	switch m {
	case rfc7591v1.TokenEndpointAuthMethodNone:
		if req.GetCodeChallenge() == "" {
			return Error{
				Code:        InvalidRequest,
				Description: "code challenge are required when token endpoint auth method is 'none'",
			}
		}
	case rfc7591v1.TokenEndpointAuthMethodClientSecretBasic,
		rfc7591v1.TokenEndpointAuthMethodClientSecretPost:
		// code challenge is recommended but not required for these methods
	default:
		return Error{
			Code:        InvalidRequest,
			Description: fmt.Sprintf("unsupported token endpoint auth method: %s", m),
		}
	}
	return nil
}

func ValidateAuthorizationRequestRedirectURI(
	client *rfc7591v1.Metadata,
	redirectURI *string,
) error {
	if len(client.RedirectUris) == 0 {
		return Error{Code: InvalidClient, Description: "client has no redirect URIs"}
	}

	if redirectURI == nil {
		if len(client.RedirectUris) != 1 {
			return Error{Code: InvalidRequest, Description: "client has multiple redirect URIs and none were provided"}
		}
		return nil
	}

	if slices.Contains(client.RedirectUris, *redirectURI) {
		return nil
	}

	// OAuth 2.1 §2.3.1: for loopback redirects, an exact match is required
	// except for the port URI component.
	if isLoopbackRedirectMatch(client.RedirectUris, *redirectURI) {
		return nil
	}

	return Error{Code: InvalidGrant, Description: "client redirect URI does not match registered redirect URIs"}
}

// isLoopbackRedirectMatch checks whether redirectURI matches any registered URI
// ignoring the port component, but only when both are loopback addresses
// (localhost or 127.0.0.1). Per OAuth 2.1 §2.3.1 and §8.4.2.
func isLoopbackRedirectMatch(registered []string, redirectURI string) bool {
	reqURL, err := url.Parse(redirectURI)
	if err != nil {
		return false
	}
	if !isLoopbackHost(reqURL.Hostname()) {
		return false
	}
	for _, reg := range registered {
		regURL, err := url.Parse(reg)
		if err != nil {
			continue
		}
		if reqURL.Scheme == regURL.Scheme &&
			reqURL.Hostname() == regURL.Hostname() &&
			reqURL.Path == regURL.Path {
			return true
		}
	}
	return false
}

func isLoopbackHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1"
}
