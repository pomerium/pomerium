package health

import (
	"errors"

	"go.opentelemetry.io/otel/attribute"
)

// Tracker tracks all health records ingested by health check reporter
type Tracker interface {
	HasStarted(Check) bool
	GetRecords() map[Check]*Record
}

// Provider is the interface that must be implemented by a health check reporter
type Provider interface {
	ReportStatus(check Check, status Status, attributes ...Attr)
	ReportError(check Check, err error, attributes ...Attr)
}

// Attr is a key-value pair that can be attached to a health check
type Attr struct {
	Key   string
	Value string
}

func (a Attr) AsOtelAttribute() attribute.KeyValue {
	return attribute.String(a.Key, a.Value)
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

func ReportRunning(check Check, attributes ...Attr) {
	provider.ReportStatus(check, StatusRunning, attributes...)
}

func ReportTerminating(check Check, attributes ...Attr) {
	provider.ReportStatus(check, StatusTerminating, attributes...)
}

func ReportStatus(check Check, status Status, attributes ...Attr) {
	provider.ReportStatus(check, status, attributes...)
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

var provider Provider = defaultProviderManager
