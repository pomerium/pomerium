package mcp

import (
	"fmt"

	"github.com/pomerium/pomerium/internal/oauth21"
	"github.com/pomerium/pomerium/internal/oauth21/gen"
)

func AuthorizeTokenRequest(
	tokReq *gen.TokenRequest,
	authReq *gen.AuthorizationRequest,
) error {
	if tokReq.GrantType != "authorization_code" {
		return fmt.Errorf("unexpected grant type: %s", tokReq.GrantType)
	}

	if tokReq.ClientId == nil {
		return fmt.Errorf("token request: missing client_id")
	} else if *tokReq.ClientId != authReq.ClientId {
		return fmt.Errorf("token request: client_id does not match authorization request")
	}

	if authReq.CodeChallengeMethod == nil || *authReq.CodeChallengeMethod == "plain" {
		if !oauth21.VerifyPKCEPlain(*tokReq.CodeVerifier, authReq.CodeChallenge) {
			return fmt.Errorf("plain: code verifier does not match code challenge")
		}
	} else if *authReq.CodeChallengeMethod == "S256" {
		if !oauth21.VerifyPKCES256(*tokReq.CodeVerifier, authReq.CodeChallenge) {
			return fmt.Errorf("S256: code verifier does not match code challenge")
		}
	} else {
		return fmt.Errorf("unsupported code challenge method: %s", *authReq.CodeChallengeMethod)
	}

	return nil
}
