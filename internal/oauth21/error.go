package oauth21

import (
	"encoding/json"
	"net/http"
)

type ErrorCode string

const (
	// InvalidRequest The request is missing a required parameter, includes an unsupported parameter value (other than grant type), repeats a parameter, includes multiple credentials, utilizes more than one mechanism for authenticating the client, contains a code_verifier although no code_challenge was sent in the authorization request, or is otherwise malformed.
	InvalidRequest ErrorCode = "invalid_request"
	// InvalidClient Client authentication failed (e.g., unknown client, no client authentication included, or unsupported authentication method). The authorization server MAY return an HTTP 401 (Unauthorized) status code to indicate which HTTP authentication schemes are supported. If the client attempted to authenticate via the Authorization request header field, the authorization server MUST respond with an HTTP 401 (Unauthorized) status code and include the WWW-Authenticate response header field matching the authentication scheme used by the client.
	InvalidClient ErrorCode = "invalid_client"
	// InvalidGrant The provided authorization grant (e.g., authorization code, resource owner credentials) or refresh token is invalid, expired, revoked, does not match the redirect URI used in the authorization request, or was issued to another client.
	InvalidGrant ErrorCode = "invalid_grant"
	// UnauthorizedClient The authenticated client is not authorized to use this authorization grant type.
	UnauthorizedClient ErrorCode = "unauthorized_client"
	// UnsupportedGrantType The authorization grant type is not supported by the authorization server.
	UnsupportedGrantType ErrorCode = "unsupported_grant_type"
	// InvalidScope The requested scope is invalid, unknown, malformed, or exceeds the scope granted by the resource owner.
	InvalidScope ErrorCode = "invalid_scope"
)

type Error struct {
	Code        ErrorCode `json:"error"`
	Description string    `json:"error_description,omitempty"`
	ErrorURI    string    `json:"error_uri,omitempty"`
}

func (e Error) Error() string {
	return string(e.Code)
}

// ErrorResponse writes an error response according to https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-12#section-3.2.4
func ErrorResponse(w http.ResponseWriter, hc int, ec ErrorCode) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(hc)
	if err := json.NewEncoder(w).Encode(Error{Code: ec}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
