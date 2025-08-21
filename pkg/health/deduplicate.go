package health

import (
	"maps"
	"sync"
)

var _ Provider = (*Deduplicator)(nil)

// Deduplicator is a health check provider that deduplicates health check reports
// i.e. it only reports a health check if the status or attributes have changed
type Deduplicator struct {
	lock     sync.Mutex
	records  map[Check]*record
	provider Provider
}

type record struct {
	status Status
	attr   map[string]string
	err    error
}

func newErrorRecord(err error, attrs []Attr) *record {
	r := &record{err: err, attr: make(map[string]string)}
	for _, a := range attrs {
		r.attr[a.Key] = a.Value
	}
	return r
}

func newRecord(status Status, err error, attrs []Attr) *record {
	r := &record{status: status, err: err, attr: make(map[string]string)}
	for _, a := range attrs {
		r.attr[a.Key] = a.Value
	}
	return r
}

func (r *record) Attr() []Attr {
	attrs := make([]Attr, 0, len(r.attr))
	for k, v := range r.attr {
		attrs = append(attrs, Attr{Key: k, Value: v})
	}
	return attrs
}

func (r *record) Equals(other *record) bool {
	return equalError(r.err, other.err) &&
		maps.Equal(r.attr, other.attr) &&
		r.status == other.status
}

func equalError(a, b error) bool {
	if a == nil || b == nil {
		return a == b //nolint:errorlint
	}
	return a.Error() == b.Error()
}

func report(p Provider, check Check, status Status, err error, attrs ...Attr) {
	if err != nil {
		p.ReportError(check, err, attrs...)
	} else {
		p.ReportStatus(check, status, attrs...)
	}
}

func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		records:  make(map[Check]*record),
		provider: &noopProvider{},
	}
}

func (d *Deduplicator) SetProvider(p Provider) {
	if p == nil {
		p = &noopProvider{}
	}
	records := d.setProvider(p)
	for check, record := range records {
		report(p, check, record.status, record.err, record.Attr()...)
	}
}

func (d *Deduplicator) setProvider(p Provider) map[Check]*record {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.provider = p
	return maps.Clone(d.records)
}

func (d *Deduplicator) swap(check Check, next *record) (provider Provider, changed bool) {
	d.lock.Lock()
	defer d.lock.Unlock()

	prev := d.records[check]
	// TODO : maybe we would want to handle out of order records from potentially happening here
	// e.g. something like:
	// if prev != nil && prev.status > next.status {
	// 	// do not change
	// }

	d.records[check] = next
	changed = prev == nil || !next.Equals(prev)
	return d.provider, changed
}

// ReportError implements the Provider interface
func (d *Deduplicator) ReportError(check Check, err error, attrs ...Attr) {
	provider, changed := d.swap(check, newErrorRecord(err, attrs))
	if changed {
		provider.ReportError(check, err, attrs...)
	}
}

func (d *Deduplicator) ReportStatus(check Check, status Status, attrs ...Attr) {
	provider, changed := d.swap(check, newRecord(status, nil, attrs))
	if changed {
		provider.ReportStatus(check, status, attrs...)
	}
}

func (d *Deduplicator) GetRecords() map[Check]*record {
	d.lock.Lock()
	defer d.lock.Unlock()
	return maps.Clone(d.records)
}

type noopProvider struct{}

func (n *noopProvider) ReportOK(Check, ...Attr) {}

func (n *noopProvider) ReportError(Check, error, ...Attr) {}

func (n *noopProvider) ReportStatus(Check, Status, ...Attr) {}
