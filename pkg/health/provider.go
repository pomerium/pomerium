package health

import (
	"errors"
)

// Attr is a key-value pair that can be attached to a health check
type Attr struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// StrAttr creates a new string attribute
func StrAttr(key, value string) Attr {
	return Attr{Key: key, Value: value}
}

// InternalErrorKey is the key used to indicate that a check failed due to some non-user facing error
const InternalErrorKey = "internal_error"

// ErrorAttr creates a new error attribute, that is used to indicate that a check failed due to some non-user facing error
func ErrorAttr(err error) Attr {
	return Attr{Key: InternalErrorKey, Value: err.Error()}
}

// ReportOK reports that a check was successful
func ReportOK(check Check, attributes ...Attr) {
	provider.ReportOK(check, attributes...)
}

var ErrInternalError = errors.New("internal error")

// ReportInternalError reports that a check failed due to an internal error
func ReportInternalError(check Check, err error, attributes ...Attr) {
	ReportError(check, ErrInternalError, append([]Attr{ErrorAttr(err)}, attributes...)...)
}

// ReportError reports that a check failed
func ReportError(check Check, err error, attributes ...Attr) {
	provider.ReportError(check, err, attributes...)
}

// Provider is the interface that must be implemented by a health check reporter
type Provider interface {
	ReportStatus(check Check, status Status, attributes ...Attr)
	ReportOK(check Check, attributes ...Attr)
	ReportError(check Check, err error, attributes ...Attr)
}

// SetProvider sets the health check provider
func SetProvider(p Provider) {
	provider.SetProvider(p)
}

var provider = NewDeduplicator()
