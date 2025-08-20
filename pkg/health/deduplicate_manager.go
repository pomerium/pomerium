package health

import (
	"log/slog"
	"maps"
	"sync"
	"sync/atomic"
)

var _ ProviderManager = (*DeduplicatorBroker)(nil)

type DeduplicatorBroker struct {
	innerVersion *atomic.Uint64
	logger       *slog.Logger
	lock         sync.Mutex
	records      map[Check]*record

	providerMu sync.RWMutex
	providers  map[ProviderID]Provider
}

func NewDeduplicatorBroker(logger *slog.Logger) *DeduplicatorBroker {
	v := &atomic.Uint64{}
	v.Store(0)
	return &DeduplicatorBroker{
		innerVersion: v,
		logger:       logger,
		lock:         sync.Mutex{},
		records:      map[Check]*record{},
		providerMu:   sync.RWMutex{},
		providers:    map[ProviderID]Provider{},
	}
}

func (d *DeduplicatorBroker) Register(id ProviderID, prov Provider) {
	d.providerMu.Lock()
	defer d.providerMu.Unlock()
	d.replay(prov)
	d.providers[id] = prov

}

func (d *DeduplicatorBroker) Deregister(id ProviderID) {
	d.providerMu.Lock()
	defer d.providerMu.Unlock()
	delete(d.providers, id)
}

func (d *DeduplicatorBroker) replay(prov Provider) {
	records := d.GetRecords()
	d.logger.With("numRecords", len(records)).Info("replaying statuses")
	for check, rec := range records {
		if rec.err != nil {
			prov.ReportError(check, rec.err, rec.Attr()...)
		} else {
			prov.ReportStatus(check, rec.status, rec.Attr()...)
		}
	}
}

// func (d *DeduplicatorBroker) reportOK(check Check, attrs ...Attr) {
// 	d.reportStatus(check, StatusRunning, attrs...)
// }

func (d *DeduplicatorBroker) reportError(check Check, err error, attrs ...Attr) {
	d.providerMu.RLock()
	defer d.providerMu.RUnlock()
	d.logger.With("providers", len(d.providers), logKeyStatus, "ERROR", "check", check).Error("reported")
	for _, prov := range d.providers {
		prov.ReportError(check, err, attrs...)
	}
}

func (d *DeduplicatorBroker) reportStatus(check Check, status Status, attrs ...Attr) {
	d.providerMu.RLock()
	defer d.providerMu.RUnlock()
	d.logger.With("providers", len(d.providers), logKeyStatus, status.String(), "check", check).Info("reported")
	for _, prov := range d.providers {
		prov.ReportStatus(check, status, attrs...)
	}
}

func (d *DeduplicatorBroker) SetProvider(_ Provider) {}

func (d *DeduplicatorBroker) swap(check Check, next *record) (changed bool) {
	d.lock.Lock()
	defer d.lock.Unlock()

	prev := d.records[check]

	if prev == nil {
		if next.err != nil {
			next.status = StatusStarting
		}
		d.records[check] = next
		return true
	}

	if next.err != nil {
		next.status = prev.status
	}

	if !prev.Equals(next) {
		d.records[check] = next
	}
	return
}

// ReportError implements the Provider interface
func (d *DeduplicatorBroker) ReportError(check Check, err error, attrs ...Attr) {
	if changed := d.swap(check, newErrorRecord(err, attrs)); changed {
		d.reportError(check, err, attrs...)
	}
}

func (d *DeduplicatorBroker) ReportStatus(check Check, status Status, attrs ...Attr) {
	if changed := d.swap(check, newRecord(status, nil, attrs)); changed {
		d.reportStatus(check, status, attrs...)
	}
}

func (d *DeduplicatorBroker) GetRecords() map[Check]*record {
	d.lock.Lock()
	defer d.lock.Unlock()
	return maps.Clone(d.records)
}
