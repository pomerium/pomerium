package oauth21

import (
	"fmt"
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
		return Error{Code: InvalidGrant, Description: "client redirect URI does not match registered redirect URIs"}
	}

	return nil
}
