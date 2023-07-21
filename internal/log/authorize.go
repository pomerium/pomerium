package log

import "strings"

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

// DefaultAuthorizeLogFields are the default authorize log fields to log.
var DefaultAuthorizeLogFields = []AuthorizeLogField{
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
	AuthorizeLogFieldHeaders.ForDebugOnly(),
}

const debugOnlyPrefix = "debug."

// IsForDebugOnly returns an authorize log field that's intended to only be logged in debug mode.
func (field AuthorizeLogField) IsForDebugOnly() (AuthorizeLogField, bool) {
	if strings.HasPrefix(string(field), debugOnlyPrefix) {
		return field[len(debugOnlyPrefix):], true
	}
	return field, false
}

// ForDebugOnly returns the authorize log field that will only be logged in debug mode.
func (field AuthorizeLogField) ForDebugOnly() AuthorizeLogField {
	if _, ok := field.IsForDebugOnly(); ok {
		return field
	}
	return debugOnlyPrefix + field
}
