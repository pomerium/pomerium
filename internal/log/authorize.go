package log

import (
	"errors"
	"fmt"
)

// An AuthorizeLogField is a field in the authorize logs.
type AuthorizeLogField string

// known authorize log fields
const (
	AuthorizeLogFieldCheckRequestID       AuthorizeLogField = "check-request-id"
	AuthorizeLogFieldBody                 AuthorizeLogField = "body"
	AuthorizeLogFieldClusterStatName      AuthorizeLogField = "cluster-stat-name"
	AuthorizeLogFieldEmail                AuthorizeLogField = "email"
	AuthorizeLogFieldEnvoyRouteChecksum   AuthorizeLogField = "envoy-route-checksum"
	AuthorizeLogFieldEnvoyRouteID         AuthorizeLogField = "envoy-route-id"
	AuthorizeLogFieldHeaders                                = AuthorizeLogField(headersFieldName)
	AuthorizeLogFieldHost                 AuthorizeLogField = "host"
	AuthorizeLogFieldIDToken              AuthorizeLogField = "id-token"
	AuthorizeLogFieldIDTokenClaims        AuthorizeLogField = "id-token-claims"
	AuthorizeLogFieldImpersonateEmail     AuthorizeLogField = "impersonate-email"
	AuthorizeLogFieldImpersonateSessionID AuthorizeLogField = "impersonate-session-id"
	AuthorizeLogFieldImpersonateUserID    AuthorizeLogField = "impersonate-user-id"
	AuthorizeLogFieldIP                   AuthorizeLogField = "ip"
	AuthorizeLogFieldMCPMethod            AuthorizeLogField = "mcp-method"
	AuthorizeLogFieldMCPTool              AuthorizeLogField = "mcp-tool"
	AuthorizeLogFieldMCPToolParameters    AuthorizeLogField = "mcp-tool-parameters"
	AuthorizeLogFieldMethod               AuthorizeLogField = "method"
	AuthorizeLogFieldPath                 AuthorizeLogField = "path"
	AuthorizeLogFieldQuery                AuthorizeLogField = "query"
	AuthorizeLogFieldRemovedGroupsCount   AuthorizeLogField = "removed-groups-count"
	AuthorizeLogFieldRequestID            AuthorizeLogField = "request-id"
	AuthorizeLogFieldRouteChecksum        AuthorizeLogField = "route-checksum"
	AuthorizeLogFieldRouteID              AuthorizeLogField = "route-id"
	AuthorizeLogFieldServiceAccountID     AuthorizeLogField = "service-account-id"
	AuthorizeLogFieldSessionID            AuthorizeLogField = "session-id"
	AuthorizeLogFieldUser                 AuthorizeLogField = "user"
)

// DefaultAuthorizeLogFields are the fields to log by default.
var DefaultAuthorizeLogFields = []AuthorizeLogField{
	AuthorizeLogFieldRequestID,
	AuthorizeLogFieldCheckRequestID,
	AuthorizeLogFieldClusterStatName,
	AuthorizeLogFieldMethod,
	AuthorizeLogFieldPath,
	AuthorizeLogFieldHost,
	AuthorizeLogFieldIP,
	AuthorizeLogFieldSessionID,
	AuthorizeLogFieldImpersonateSessionID,
	AuthorizeLogFieldImpersonateUserID,
	AuthorizeLogFieldImpersonateEmail,
	AuthorizeLogFieldRemovedGroupsCount,
	AuthorizeLogFieldServiceAccountID,
	AuthorizeLogFieldUser,
	AuthorizeLogFieldEmail,
	AuthorizeLogFieldEnvoyRouteChecksum,
	AuthorizeLogFieldEnvoyRouteID,
	AuthorizeLogFieldRouteChecksum,
	AuthorizeLogFieldRouteID,
}

// ErrUnknownAuthorizeLogField indicates that an authorize log field is unknown.
var ErrUnknownAuthorizeLogField = errors.New("unknown authorize log field")

var authorizeLogFieldLookup = map[AuthorizeLogField]struct{}{
	AuthorizeLogFieldCheckRequestID:       {},
	AuthorizeLogFieldBody:                 {},
	AuthorizeLogFieldClusterStatName:      {},
	AuthorizeLogFieldEmail:                {},
	AuthorizeLogFieldEnvoyRouteChecksum:   {},
	AuthorizeLogFieldEnvoyRouteID:         {},
	AuthorizeLogFieldHeaders:              {},
	AuthorizeLogFieldHost:                 {},
	AuthorizeLogFieldIDToken:              {},
	AuthorizeLogFieldIDTokenClaims:        {},
	AuthorizeLogFieldImpersonateEmail:     {},
	AuthorizeLogFieldImpersonateSessionID: {},
	AuthorizeLogFieldImpersonateUserID:    {},
	AuthorizeLogFieldIP:                   {},
	AuthorizeLogFieldMCPMethod:            {},
	AuthorizeLogFieldMCPTool:              {},
	AuthorizeLogFieldMCPToolParameters:    {},
	AuthorizeLogFieldMethod:               {},
	AuthorizeLogFieldPath:                 {},
	AuthorizeLogFieldQuery:                {},
	AuthorizeLogFieldRemovedGroupsCount:   {},
	AuthorizeLogFieldRequestID:            {},
	AuthorizeLogFieldRouteChecksum:        {},
	AuthorizeLogFieldRouteID:              {},
	AuthorizeLogFieldServiceAccountID:     {},
	AuthorizeLogFieldSessionID:            {},
	AuthorizeLogFieldUser:                 {},
}

// Validate returns an error if the authorize log field is invalid.
func (field AuthorizeLogField) Validate() error {
	if _, ok := GetHeaderField(field); ok {
		return nil
	}

	_, ok := authorizeLogFieldLookup[field]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownAuthorizeLogField, field)
	}

	return nil
}
