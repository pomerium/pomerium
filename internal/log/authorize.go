package log

import (
	"errors"
	"fmt"

	"github.com/rs/zerolog"
)

// An AuthorizeLogField is a field in the authorize logs.
type AuthorizeLogField string

// known authorize log fields
const (
	AuthorizeLogFieldCheckRequestID       AuthorizeLogField = "check-request-id"
	AuthorizeLogFieldEmail                AuthorizeLogField = "email"
	AuthorizeLogFieldHeaders                                = AuthorizeLogField(headersFieldName)
	AuthorizeLogFieldHost                 AuthorizeLogField = "host"
	AuthorizeLogFieldIDToken              AuthorizeLogField = "id-token"
	AuthorizeLogFieldIDTokenClaims        AuthorizeLogField = "id-token-claims"
	AuthorizeLogFieldImpersonateEmail     AuthorizeLogField = "impersonate-email"
	AuthorizeLogFieldImpersonateSessionID AuthorizeLogField = "impersonate-session-id"
	AuthorizeLogFieldImpersonateUserID    AuthorizeLogField = "impersonate-user-id"
	AuthorizeLogFieldIP                   AuthorizeLogField = "ip"
	AuthorizeLogFieldMethod               AuthorizeLogField = "method"
	AuthorizeLogFieldPath                 AuthorizeLogField = "path"
	AuthorizeLogFieldQuery                AuthorizeLogField = "query"
	AuthorizeLogFieldRequestID            AuthorizeLogField = "request-id"
	AuthorizeLogFieldServiceAccountID     AuthorizeLogField = "service-account-id"
	AuthorizeLogFieldSessionID            AuthorizeLogField = "session-id"
	AuthorizeLogFieldUser                 AuthorizeLogField = "user"
)

var defaultAuthorizeLogFields = []AuthorizeLogField{
	AuthorizeLogFieldRequestID,
	AuthorizeLogFieldCheckRequestID,
	AuthorizeLogFieldMethod,
	AuthorizeLogFieldPath,
	AuthorizeLogFieldHost,
	AuthorizeLogFieldIP,
	AuthorizeLogFieldSessionID,
	AuthorizeLogFieldImpersonateSessionID,
	AuthorizeLogFieldImpersonateUserID,
	AuthorizeLogFieldImpersonateEmail,
	AuthorizeLogFieldServiceAccountID,
	AuthorizeLogFieldUser,
	AuthorizeLogFieldEmail,
}

var defaultDebugAuthorizeLogFields = append(defaultAuthorizeLogFields, AuthorizeLogFieldHeaders)

// DefaultAuthorizeLogFields returns the default authorize log fields.
func DefaultAuthorizeLogFields() []AuthorizeLogField {
	if zerolog.GlobalLevel() <= zerolog.DebugLevel {
		return defaultDebugAuthorizeLogFields
	}
	return defaultAuthorizeLogFields
}

// ErrUnknownAuthorizeLogField indicates that an authorize log field is unknown.
var ErrUnknownAuthorizeLogField = errors.New("unknown authorize log field")

var authorizeLogFieldLookup = map[AuthorizeLogField]struct{}{
	AuthorizeLogFieldCheckRequestID:       {},
	AuthorizeLogFieldEmail:                {},
	AuthorizeLogFieldHeaders:              {},
	AuthorizeLogFieldHost:                 {},
	AuthorizeLogFieldIDToken:              {},
	AuthorizeLogFieldIDTokenClaims:        {},
	AuthorizeLogFieldImpersonateEmail:     {},
	AuthorizeLogFieldImpersonateSessionID: {},
	AuthorizeLogFieldImpersonateUserID:    {},
	AuthorizeLogFieldIP:                   {},
	AuthorizeLogFieldMethod:               {},
	AuthorizeLogFieldPath:                 {},
	AuthorizeLogFieldQuery:                {},
	AuthorizeLogFieldRequestID:            {},
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
