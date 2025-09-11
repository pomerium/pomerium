package health

import (
	"github.com/pomerium/pomerium/internal/log"
)

var (
	_ ProviderManager = (*ProviderAggregator)(nil)
	_ Provider        = (*ProviderAggregator)(nil)
)

type ProviderID string

const (
	ProviderHTTP    = "ProviderHTTP"
	ProviderMetrics = "ProviderMetrics"
	ProviderGRPC    = "ProviderGRPC"
)

var defaultProviderManager = NewManager()

type ProviderManager interface {
	// Register adds a provider to the manager.
	// When a provider is registered, all tracked health conditions by the ProviderManager
	// are synced to the provider being registered
	// Re-registering a provider updates it in place
	Register(id ProviderID, prov Provider)
	// Deregister removes the given provider
	Deregister(id ProviderID)

	// Provider : the manager is itself a Provider that brokers status reports to other
	// Providers
	Provider
	// Tracker: the manager is itself a health tracker
	Tracker
}

type ProviderAggregator struct {
	deduplicator *DeduplicatorBroker
}

func NewManager() ProviderManager {
	logger := log.With().Str("component", "health-manager")
	return &ProviderAggregator{
		deduplicator: NewDeduplicatorBroker(logger.Logger()),
	}
}

func (p *ProviderAggregator) Register(id ProviderID, prov Provider) {
	p.deduplicator.Register(id, prov)
}

func (p *ProviderAggregator) Deregister(id ProviderID) {
	p.deduplicator.Deregister(id)
}

func (p *ProviderAggregator) GetRecords() map[Check]*Record {
	return p.deduplicator.GetRecords()
}

func (p *ProviderAggregator) ReportError(check Check, err error, attrs ...Attr) {
	p.deduplicator.ReportError(check, err, attrs...)
}

func (p *ProviderAggregator) ReportStatus(check Check, status Status, attrs ...Attr) {
	p.deduplicator.ReportStatus(check, status, attrs...)
}

type noopProviderManager struct{}

func (n *noopProviderManager) Register(_ ProviderID, _ Provider)         {}
func (n *noopProviderManager) Deregister(_ ProviderID)                   {}
func (n *noopProviderManager) Reset()                                    {}
func (n *noopProviderManager) ReportStatus(_ Check, _ Status, _ ...Attr) {}
func (n *noopProviderManager) ReportOK(_ Check, _ ...Attr)               {}
func (n *noopProviderManager) ReportError(_ Check, _ error, _ ...Attr)   {}
func (n *noopProviderManager) GetRecords() map[Check]*Record {
	return map[Check]*Record{}
}

var _ ProviderManager = (*noopProviderManager)(nil)

func GetProviderManager() ProviderManager {
	return defaultProviderManager
}
