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
	attr map[string]string
	err  error
}

func newOKRecord(attrs []Attr) *record {
	return newRecord(nil, attrs)
}

func newErrorRecord(err error, attrs []Attr) *record {
	return newRecord(err, attrs)
}

func newRecord(err error, attrs []Attr) *record {
	r := &record{err: err, attr: make(map[string]string)}
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
		maps.Equal(r.attr, other.attr)
}

func equalError(a, b error) bool {
	if a == nil || b == nil {
		return a == b //nolint:errorlint
	}
	return a.Error() == b.Error()
}

func report(p Provider, check Check, err error, attrs ...Attr) {
	if err != nil {
		p.ReportError(check, err, attrs...)
	} else {
		p.ReportOK(check, attrs...)
	}
}

func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		records:  make(map[Check]*record),
		provider: &noopProvider{},
	}
}

func (d *Deduplicator) SetProvider(p Provider) {
	d.setProvider(p)()
}

func (d *Deduplicator) setProvider(p Provider) func() {
	d.lock.Lock()
	defer d.lock.Unlock()

	if p == nil {
		p = &noopProvider{}
	}
	d.provider = p
	records := maps.Clone(d.records)

	return func() {
		for check, record := range records {
			report(p, check, record.err, record.Attr()...)
		}
	}
}

func (d *Deduplicator) update(check Check, next *record) func() {
	d.lock.Lock()
	defer d.lock.Unlock()

	prev := d.records[check]
	d.records[check] = next
	if prev != nil && next.Equals(prev) {
		return func() {}
	}

	p := d.provider
	return func() {
		report(p, check, next.err, next.Attr()...)
	}
}

// ReportError implements the Provider interface
func (d *Deduplicator) ReportError(check Check, err error, attrs ...Attr) {
	d.update(check, newErrorRecord(err, attrs))()
}

// ReportOK implements the Provider interface
func (d *Deduplicator) ReportOK(check Check, attrs ...Attr) {
	d.update(check, newOKRecord(attrs))()
}

type noopProvider struct{}

func (n *noopProvider) ReportOK(Check, ...Attr) {}

func (n *noopProvider) ReportError(Check, error, ...Attr) {}
