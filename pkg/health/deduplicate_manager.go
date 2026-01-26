package health

import (
	"maps"
	"sync"
	"sync/atomic"

	"github.com/rs/zerolog"
)

const (
	logKeyStatus = "health-status"
)

var _ ProviderManager = (*DeduplicatorBroker)(nil)

type DeduplicatorBroker struct {
	innerVersion *atomic.Uint64
	logger       zerolog.Logger
	lock         sync.RWMutex
	records      map[Check]*Record

	providerMu sync.RWMutex
	providers  map[ProviderID]Provider
}

func NewDeduplicatorBroker(logger zerolog.Logger) *DeduplicatorBroker {
	v := &atomic.Uint64{}
	v.Store(0)
	return &DeduplicatorBroker{
		innerVersion: v,
		logger:       logger,
		lock:         sync.RWMutex{},
		records:      map[Check]*Record{},
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
	d.logger.Debug().Int("numRecords", len(records)).Msg("replaying health events")

	for check, rec := range records {
		if rec.err != nil {
			prov.ReportError(check, rec.err, rec.Attr()...)
		} else {
			prov.ReportStatus(check, rec.status, rec.Attr()...)
		}
	}
}

func (d *DeduplicatorBroker) reportError(check Check, err error, attrs ...Attr) {
	d.providerMu.RLock()
	defer d.providerMu.RUnlock()
	d.logger.Debug().Int("numProviders", len(d.providers)).
		Str(logKeyStatus, "ERROR").
		Str("check", string(check)).Msg("health reported")

	for _, prov := range d.providers {
		prov.ReportError(check, err, attrs...)
	}
}

func (d *DeduplicatorBroker) reportStatus(check Check, status Status, attrs ...Attr) {
	d.providerMu.RLock()
	defer d.providerMu.RUnlock()
	for _, prov := range d.providers {
		prov.ReportStatus(check, status, attrs...)
	}
	d.logger.Debug().Int("providers", len(d.providers)).
		Str(logKeyStatus, status.String()).
		Str("check", string(check)).Msg("reported")
}

func (d *DeduplicatorBroker) SetProvider(_ Provider) {}

func (d *DeduplicatorBroker) swap(check Check, next *Record) (changed bool) {
	d.lock.Lock()
	defer d.lock.Unlock()

	prev := d.records[check]

	if prev == nil {
		if next.err != nil {
			next.status = StatusUnknown
		}
		d.records[check] = next
		return true
	}

	if next.err != nil {
		next.status = prev.status
	}

	if !prev.Equals(next) {
		d.records[check] = next
		return true
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

func (d *DeduplicatorBroker) GetRecords() map[Check]*Record {
	d.lock.RLock()
	defer d.lock.RUnlock()
	return maps.Clone(d.records)
}

func (d *DeduplicatorBroker) HasStarted(check Check) bool {
	d.lock.RLock()
	defer d.lock.RUnlock()
	r, ok := d.records[check]
	if !ok {
		return false
	}
	return r.status >= StatusRunning
}
