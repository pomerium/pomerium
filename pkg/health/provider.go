package health

import (
	"errors"
	"sync"
)

// Attr is a key-value pair that can be attached to a health check
type Attr struct {
	Key   string
	Value string
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
	p := defaultProvider.Load()
	if p != nil {
		p.ReportOK(check, attributes...)
	}
}

var ErrInternalError = errors.New("internal error")

// ReportInternalError reports that a check failed due to an internal error
func ReportInternalError(check Check, err error, attributes ...Attr) {
	ReportError(check, ErrInternalError, append([]Attr{ErrorAttr(err)}, attributes...)...)
}

// ReportError reports that a check failed
func ReportError(check Check, err error, attributes ...Attr) {
	p := defaultProvider.Load()
	if p != nil {
		p.ReportError(check, err, attributes...)
	}
}

// Provider is the interface that must be implemented by a health check reporter
type Provider interface {
	ReportOK(check Check, attributes ...Attr)
	ReportError(check Check, err error, attributes ...Attr)
}

// SetProvider sets the health check provider
func SetProvider(p Provider) {
	if p != nil {
		p = NewDeduplicator(p)
	}
	defaultProvider.Store(p)
}

type providerStore struct {
	sync.RWMutex
	provider Provider
}

func (p *providerStore) Load() Provider {
	p.RLock()
	defer p.RUnlock()

	return p.provider
}

func (p *providerStore) Store(provider Provider) {
	p.Lock()
	defer p.Unlock()

	p.provider = provider
}

var defaultProvider providerStore
