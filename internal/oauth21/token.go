package oauth21

import (
	"fmt"
	"net/http"

	"buf.build/go/protovalidate"

	"github.com/pomerium/pomerium/internal/oauth21/gen"
)

func ParseTokenRequest(r *http.Request) (*gen.TokenRequest, error) {
	err := r.ParseForm()
	if err != nil {
		return nil, fmt.Errorf("failed to parse form: %w", err)
	}

	// extract client credentials from HTTP Basic Authorization header, if present
	basicID, basicSecret, basicOK := r.BasicAuth()

	v := &gen.TokenRequest{
		GrantType:    r.Form.Get("grant_type"),
		Code:         optionalFormParam(r, "code"),
		CodeVerifier: optionalFormParam(r, "code_verifier"),
		ClientId:     optionalFormParam(r, "client_id"),
		RefreshToken: optionalFormParam(r, "refresh_token"),
		Scope:        optionalFormParam(r, "scope"),
		ClientSecret: optionalFormParam(r, "client_secret"),
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
