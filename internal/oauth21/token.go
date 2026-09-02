package oauth21

import (
	"fmt"
	"net/http"

	"buf.build/go/protovalidate"

	"github.com/pomerium/pomerium/internal/oauth21/gen"
)

// ClientAssertionTypeJWTBearer is the client_assertion_type value for the JWT
// profile, RFC 7523 Section 2.2. It is not the Section 2.1 grant type URN.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec

func ParseTokenRequest(r *http.Request) (*gen.TokenRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, fmt.Errorf("failed to parse form: %w", err)
	}

	// extract client credentials from HTTP Basic Authorization header, if present
	basicID, basicSecret, basicOK := r.BasicAuth()

	v := &gen.TokenRequest{
		GrantType:           r.Form.Get("grant_type"),
		Code:                optionalFormParam(r, "code"),
		CodeVerifier:        optionalFormParam(r, "code_verifier"),
		ClientId:            optionalFormParam(r, "client_id"),
		RefreshToken:        optionalFormParam(r, "refresh_token"),
		Scope:               optionalFormParam(r, "scope"),
		ClientSecret:        optionalFormParam(r, "client_secret"),
		ClientAssertion:     optionalFormParam(r, "client_assertion"),
		ClientAssertionType: optionalFormParam(r, "client_assertion_type"),
	}

	if basicOK {
		if v.ClientId == nil && basicID != "" {
			v.ClientId = &basicID
		}
		if v.ClientSecret == nil && basicSecret != "" {
			v.ClientSecret = &basicSecret
		}
	}

	err = protovalidate.Validate(v)
	if err != nil {
		return nil, fmt.Errorf("failed to validate token request: %w", err)
	}

	return v, nil
}
