package health

import (
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

// ReportOK reports that a check was successful
func ReportOK(check Check, attributes ...Attr) {
	p := defaultProvider.Load()
	if p != nil {
		p.ReportOK(check, attributes...)
	}
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
	defaultProvider.Store(NewDeduplicator(p))
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
