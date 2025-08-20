package health

import (
	"log/slog"
)

var _ ProviderManager = (*ProviderAggregator)(nil)
var _ Provider = (*ProviderAggregator)(nil)

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

	// Provider : the manager is itself a Provider that brokers status reports to other
	// Providers
	Provider
	// Tracker: the manager is itself a health tracker
	Tracker
}

type ProviderAggregator struct {

	// TODO : probably worth reworking deduplicator to accept multiple downstream providers to avoid
	// maintaing a cache in each downstream provider that might be interested in doing so itself
	// which is essentially what we are doing in the aggregator
	deduplicator *DeduplicatorBroker
	logger       *slog.Logger
}

func NewManager() ProviderManager {
	logger := slog.Default().With("component", "health-manager")
	return &ProviderAggregator{
		deduplicator: NewDeduplicatorBroker(logger),
		logger:       logger,
	}
}

func (p *ProviderAggregator) Register(id ProviderID, prov Provider) {
	p.deduplicator.Register(id, prov)
}

func (p *ProviderAggregator) Deregister(id ProviderID) {
	p.deduplicator.Deregister(id)
}

func (p *ProviderAggregator) GetRecords() map[Check]*record {
	return p.deduplicator.GetRecords()
}

func (p *ProviderAggregator) ReportError(check Check, err error, attrs ...Attr) {
	p.deduplicator.ReportError(check, err, attrs...)
}

func (p *ProviderAggregator) ReportStatus(check Check, status Status, attrs ...Attr) {
	p.deduplicator.ReportStatus(check, status, attrs...)
}

type noopProviderManager struct{}

func (n *noopProviderManager) Register(_ ProviderID, _ Provider)                           {}
func (n *noopProviderManager) Deregister(_ ProviderID)                                     {}
func (n *noopProviderManager) Reset()                                                      {}
func (n *noopProviderManager) ReportStatus(check Check, status Status, attributes ...Attr) {}
func (n *noopProviderManager) ReportOK(check Check, attributes ...Attr)                    {}
func (n *noopProviderManager) ReportError(check Check, err error, attributes ...Attr)      {}
func (n *noopProviderManager) GetRecords() map[Check]*record {
	return map[Check]*record{}
}

var _ ProviderManager = (*noopProviderManager)(nil)

func GetProviderManager() ProviderManager {
	return defaultProviderManager
}

func SetProviderManager(mgr ProviderManager) {
	defaultProviderManager = mgr
}
