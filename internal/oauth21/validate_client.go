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

	if !slices.Contains(client.RedirectUris, *redirectURI) {
		// RFC 8252 §7.3 (Loopback Interface Redirection): authorization servers
		// MUST allow any port for loopback redirect URIs. MCP CLI clients
		// (e.g. Claude Code) advertise port-less loopback redirect_uris in
		// CIMD but request specific ephemeral ports at runtime, so a strict
		// slices.Contains would always fail. Allow when scheme + loopback host
		// + path match regardless of port.
		matched := false
		for _, allowed := range client.RedirectUris {
			if matchLoopbackRedirect(allowed, *redirectURI) {
				matched = true
				break
			}
		}
		if !matched {
			return Error{Code: InvalidGrant, Description: "client redirect URI does not match registered redirect URIs"}
		}
	}

	return nil
}

// matchLoopbackRedirect implements RFC 8252 §7.3: loopback HTTP redirect URIs
// (localhost / 127.0.0.1 / ::1) match regardless of port if scheme + host + path
// match.
func matchLoopbackRedirect(allowed, requested string) bool {
	a, err := url.Parse(allowed)
	if err != nil {
		return false
	}
	r, err := url.Parse(requested)
	if err != nil {
		return false
	}
	if a.Scheme != "http" || r.Scheme != "http" {
		return false
	}
	if !isLoopbackHost(a.Hostname()) || !isLoopbackHost(r.Hostname()) {
		return false
	}
	if a.Hostname() != r.Hostname() {
		return false
	}
	return a.Path == r.Path
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}
