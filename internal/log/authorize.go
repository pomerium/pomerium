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
	AuthorizeLogFieldHeaders              AuthorizeLogField = "headers"
	AuthorizeLogFieldHost                 AuthorizeLogField = "host"
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

// DefaultAuthorizeLogFields returns the default authorize log fields.
func DefaultAuthorizeLogFields() []AuthorizeLogField {
	fields := []AuthorizeLogField{
		AuthorizeLogFieldRequestID,
		AuthorizeLogFieldCheckRequestID,
		AuthorizeLogFieldMethod,
		AuthorizeLogFieldPath,
		AuthorizeLogFieldHost,
		AuthorizeLogFieldQuery,
		AuthorizeLogFieldIP,
		AuthorizeLogFieldSessionID,
		AuthorizeLogFieldImpersonateSessionID,
		AuthorizeLogFieldImpersonateUserID,
		AuthorizeLogFieldImpersonateEmail,
		AuthorizeLogFieldServiceAccountID,
		AuthorizeLogFieldUser,
		AuthorizeLogFieldEmail,
	}
	if zerolog.GlobalLevel() <= zerolog.DebugLevel {
		fields = append(fields, AuthorizeLogFieldHeaders)
	}
	return fields
}

// ErrUnknownAuthorizeLogField indicates that an authorize log field is unknown.
var ErrUnknownAuthorizeLogField = errors.New("unknown authorize log field")

var authorizeLogFieldLookup = map[AuthorizeLogField]struct{}{
	AuthorizeLogFieldCheckRequestID:       {},
	AuthorizeLogFieldEmail:                {},
	AuthorizeLogFieldHeaders:              {},
	AuthorizeLogFieldHost:                 {},
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
	_, ok := authorizeLogFieldLookup[field]
	if !ok {
		return fmt.Errorf("%w: %s", ErrUnknownAuthorizeLogField, field)
	}

	return nil
}
