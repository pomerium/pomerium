package health

import (
	"log/slog"
	"sync"
)

type ProviderID string

const (
	ProviderHTTP    = "ProviderHTTP"
	ProviderMetrics = "ProviderMetrics"
	ProviderGRPC    = "ProviderGRPC"
)

var (
	defaultProviderManager ProviderManager = &noopProviderManager{}
)

type ProviderManager interface {
	// Register adds a provider to the manager.
	// When a provider is registered, all tracked health conditions by the ProviderManager
	// are synced to the provider being registered
	// Re-registering a provider updates it in place
	Register(id ProviderID, prov Provider)
	// Deregister removes the given provider
	Deregister(id ProviderID)
	// Reset resets all known health conditions the health provider has tracked to
	// the status StatusStarting, and re-broadcasts each status to every
	// registered provider
	Reset()
}

type ProviderAggregator struct {
	providerMu *sync.RWMutex
	contents   map[ProviderID]Provider

	// TODO : probably worth reworking deduplicator to accept multiple downstream providers to avoid
	// maintaing a cache in each downstream provider that might be interested in doing so itself
	// which is essentially what we are doing in the aggregator
	deduplicator *Deduplicator
	logger       *slog.Logger
}

func NewProviderAggregator() *ProviderAggregator {
	return &ProviderAggregator{
		providerMu:   &sync.RWMutex{},
		contents:     make(map[ProviderID]Provider),
		deduplicator: NewDeduplicator(),
		logger:       slog.Default(),
	}
}

func (p *ProviderAggregator) Register(id ProviderID, prov Provider) {
	p.providerMu.Lock()
	defer p.providerMu.Unlock()
	p.logger.With("id", string(id)).Info("registered provider")
	p.replay(prov)
	p.contents[id] = prov
}

func (p *ProviderAggregator) replay(prov Provider) {
	records := p.deduplicator.GetRecords()
	p.logger.With("numRecords", len(records)).Info("replaying statues")
	for check, rec := range records {
		if rec.err != nil {
			prov.ReportError(check, rec.err, rec.Attr()...)
		} else {
			prov.ReportOK(check, rec.Attr()...)
		}
	}
}

func (p *ProviderAggregator) Deregister(id ProviderID) {
	p.providerMu.Lock()
	defer p.providerMu.Unlock()
	p.logger.With("id", string(id)).Info("deregistered provider")
	delete(p.contents, id)
}

func (p *ProviderAggregator) Reset() {
	p.providerMu.RLock()
	defer p.providerMu.RUnlock()
	records := p.deduplicator.GetRecords()
	p.logger.With("numRecords", len(records), "numProviders", len(p.contents)).Info("resetting all tracked statuses")
	// 1. Reset all tracked statuses to StatusStarting
	for check, record := range records {
		// TODO: preserve attributes?
		p.deduplicator.ReportStatus(check, StatusStarted, record.Attr()...)
	}

	//2. Replay for each provider
	for _, prov := range p.contents {
		p.replay(prov)
	}

}

var _ ProviderManager = (*ProviderAggregator)(nil)
var _ Provider = (*ProviderAggregator)(nil)

func (p *ProviderAggregator) ReportOK(check Check, attrs ...Attr) {
	p.providerMu.RLock()
	defer p.providerMu.RUnlock()
	p.logger.
		With("status", StatusRunning.String(), "numProviders", len(p.contents), "check", check, "numAttrs", len(attrs)).
		Info("reported status")
	p.deduplicator.ReportOK(check, attrs...)
	for _, provider := range p.contents {
		provider.ReportOK(check, attrs...)
	}
}

func (p *ProviderAggregator) ReportError(check Check, err error, attrs ...Attr) {
	p.providerMu.RLock()
	defer p.providerMu.RUnlock()
	p.logger.
		With("status", StatusError.String(), "numProviders", len(p.contents), "check", check, "numAttrs", len(attrs)).
		Info("reported status")
	p.deduplicator.ReportError(check, err, attrs...)
	for _, provider := range p.contents {
		provider.ReportError(check, err, attrs...)
	}
}

func (p *ProviderAggregator) ReportStatus(check Check, status Status, attrs ...Attr) {
	p.providerMu.RLock()
	defer p.providerMu.RUnlock()
	p.logger.
		With("status", status.String(), "numProviders", len(p.contents), "check", check, "numAttrs", len(attrs)).
		Info("reported status")
	p.deduplicator.ReportStatus(check, status, attrs...)
	for _, provider := range p.contents {
		provider.ReportStatus(check, status, attrs...)
	}
}

type noopProviderManager struct{}

func (n *noopProviderManager) Register(_ ProviderID, _ Provider) {}
func (n *noopProviderManager) Deregister(_ ProviderID)           {}
func (n *noopProviderManager) Reset()                            {}

var _ ProviderManager = (*noopProviderManager)(nil)

func GetProviderManager() ProviderManager {
	return defaultProviderManager
}

func SetProviderManager(mgr ProviderManager) {
	defaultProviderManager = mgr
}
