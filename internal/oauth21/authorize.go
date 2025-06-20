package oauth21

import (
	"fmt"
	"net/http"

	"github.com/pomerium/pomerium/internal/oauth21/gen"
)

// ParseCodeGrantAuthorizeRequest parses the authorization request for the code grant flow.
// see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-4.1.1
// scopes are ignored
func ParseCodeGrantAuthorizeRequest(r *http.Request) (*gen.AuthorizationRequest, error) {
	if err := r.ParseForm(); err != nil {
		return nil, fmt.Errorf("failed to parse form: %w", err)
	}

	v := &gen.AuthorizationRequest{
		ClientId:            r.Form.Get("client_id"),
		RedirectUri:         optionalFormParam(r, "redirect_uri"),
		ResponseType:        r.Form.Get("response_type"),
		State:               optionalFormParam(r, "state"),
		CodeChallenge:       optionalFormParam(r, "code_challenge"),
		CodeChallengeMethod: optionalFormParam(r, "code_challenge_method"),
	}

	return v, nil
}
