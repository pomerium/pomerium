package oauth21

import (
	"slices"

	"github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
)

func ValidateAuthorizationRequest(
	client *rfc7591v1.ClientRegistrationRequest,
	req *gen.AuthorizationRequest,
) error {
	if err := ValidateAuthorizationRequestRedirectURI(client, req.RedirectUri); err != nil {
		return err
	}
	return nil
}

func ValidateAuthorizationRequestRedirectURI(
	client *rfc7591v1.ClientRegistrationRequest,
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
