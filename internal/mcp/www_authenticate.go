package mcp

import (
	"strings"

	"github.com/shogo82148/go-sfv"
)

// WWWAuthenticateParams represents parsed parameters from a Bearer WWW-Authenticate header.
// Used when Pomerium acts as a client to remote MCP servers, parsing the upstream's 401 response.
type WWWAuthenticateParams struct {
	// Realm is the optional protection realm.
	Realm string

	// Error is the error code, e.g., "insufficient_scope" (RFC 6750 §3.1).
	Error string

	// ErrorDescription is a human-readable error description.
	ErrorDescription string

	// Scope contains the required scopes (space-delimited in the header per RFC 6750 §3).
	// Per MCP spec, scope from WWW-Authenticate takes priority over scopes_supported from PRM.
	Scope []string

	// ResourceMetadata is the URL to fetch Protected Resource Metadata (RFC 9728 §5.1).
	ResourceMetadata string
}

// ParseWWWAuthenticate parses a Bearer WWW-Authenticate header value using go-sfv.
// It strips the "Bearer " prefix and decodes the remainder as an SFV dictionary,
// matching the encoding pattern used in SetWWWAuthenticateHeader.
//
// Returns nil if the header is empty, not a Bearer challenge, or has malformed SFV.
func ParseWWWAuthenticate(value string) *WWWAuthenticateParams {
	if !strings.HasPrefix(value, "Bearer ") {
		return nil
	}

	dict, err := sfv.DecodeDictionary([]string{strings.TrimPrefix(value, "Bearer ")})
	if err != nil {
		return nil
	}

	params := &WWWAuthenticateParams{}
	for _, member := range dict {
		s, ok := member.Item.Value.(string)
		if !ok {
			continue
		}
		switch member.Key {
		case "resource_metadata":
			params.ResourceMetadata = s
		case "scope":
			params.Scope = strings.Fields(s)
		case "error":
			params.Error = s
		case "error_description":
			params.ErrorDescription = s
		case "realm":
			params.Realm = s
		}
	}
	return params
}
