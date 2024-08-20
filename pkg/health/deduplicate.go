package health

import (
	"maps"
	"sync"
)

var _ Provider = (*deduplicator)(nil)

// deduplicator is a health check provider that deduplicates health check reports
// i.e. it only reports a health check if the status or attributes have changed
type deduplicator struct {
	seen     sync.Map
	provider Provider
}

type record struct {
	attr map[string]string
	err  *string
}

func newOKRecord(attrs []Attr) *record {
	return newRecord(nil, attrs)
}

func newErrorRecord(err error, attrs []Attr) *record {
	errTxt := err.Error()
	return newRecord(&errTxt, attrs)
}

func newRecord(err *string, attrs []Attr) *record {
	r := &record{err: err, attr: make(map[string]string)}
	for _, a := range attrs {
		r.attr[a.Key] = a.Value
	}
	return r
}

func (r *record) Equals(other *record) bool {
	return r.equalError(other) &&
		maps.Equal(r.attr, other.attr)
}

func (r *record) equalError(other *record) bool {
	if r.err == nil || other.err == nil {
		return r.err == other.err
	}
	return *r.err == *other.err
}

func NewDeduplicator(provider Provider) Provider {
	return &deduplicator{provider: provider}
}

func (d *deduplicator) swap(check Check, next *record) *record {
	prev, there := d.seen.Swap(check, next)
	if !there {
		return nil
	}
	return prev.(*record)
}

// ReportError implements the Provider interface
func (d *deduplicator) ReportError(check Check, err error, attrs ...Attr) {
	cur := newErrorRecord(err, attrs)
	prev := d.swap(check, cur)
	if prev == nil || !cur.Equals(prev) {
		d.provider.ReportError(check, err, attrs...)
	}
}

// ReportOK implements the Provider interface
func (d *deduplicator) ReportOK(check Check, attrs ...Attr) {
	cur := newOKRecord(attrs)
	prev := d.swap(check, cur)
	if prev == nil || !cur.Equals(prev) {
		d.provider.ReportOK(check, attrs...)
	}
}
