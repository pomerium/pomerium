package databroker

import (
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// RecordSetBundle is an index of databroker records by type
type RecordSetBundle map[string]RecordSet

// RecordSet is an index of databroker records by their id.
type RecordSet map[string]*Record

// RecordTypes returns the types of records in the bundle.
func (rsb RecordSetBundle) RecordTypes() []string {
	types := make([]string, 0, len(rsb))
	for typ := range rsb {
		types = append(types, typ)
	}
	return types
}

// Add adds a record to the bundle.
func (rsb RecordSetBundle) Add(record *Record) {
	rs, ok := rsb[record.GetType()]
	if !ok {
		rs = make(RecordSet)
		rsb[record.GetType()] = rs
	}
	rs[record.GetId()] = record
}

// GetAdded returns the records that are in other but not in rsb.
func (rsb RecordSetBundle) GetAdded(other RecordSetBundle) RecordSetBundle {
	added := make(RecordSetBundle)
	for otherType, otherRS := range other {
		rs, ok := rsb[otherType]
		if !ok {
			added[otherType] = otherRS
			continue
		}
		rss := rs.GetAdded(other[otherType])
		if len(rss) > 0 {
			added[otherType] = rss
		}
	}
	return added
}

// GetRemoved returns the records that are in rs but not in other.
func (rsb RecordSetBundle) GetRemoved(other RecordSetBundle) RecordSetBundle {
	return other.GetAdded(rsb)
}

// GetModified returns the records that are in both rs and other but have different data.
func (rsb RecordSetBundle) GetModified(other RecordSetBundle) RecordSetBundle {
	modified := make(RecordSetBundle)
	for otherType, otherRS := range other {
		rs, ok := rsb[otherType]
		if !ok {
			continue
		}
		m := rs.GetModified(otherRS)
		if len(m) > 0 {
			modified[otherType] = m
		}
	}
	return modified
}

// GetAdded returns the records that are in other but not in rs.
func (rs RecordSet) GetAdded(other RecordSet) RecordSet {
	added := make(RecordSet)
	for id, record := range other {
		if _, ok := rs[id]; !ok {
			added[id] = record
		}
	}
	return added
}

// GetRemoved returns the records that are in rs but not in other.
func (rs RecordSet) GetRemoved(other RecordSet) RecordSet {
	return other.GetAdded(rs)
}

// GetModified returns the records that are in both rs and other but have different data.
// by comparing the protobuf bytes of the payload.
func (rs RecordSet) GetModified(other RecordSet) RecordSet {
	modified := make(RecordSet)
	for id, record := range other {
		otherRecord, ok := rs[id]
		if !ok {
			continue
		}

		if !proto.Equal(record, otherRecord) {
			modified[id] = record
		}
	}
	return modified
}

// Flatten returns all records in the set.
func (rs RecordSet) Flatten() []*Record {
	records := make([]*Record, 0, len(rs))
	for _, record := range rs {
		records = append(records, record)
	}
	return records
}

// Flatten returns all records in the bundle.
func (rsb RecordSetBundle) Flatten() []*Record {
	records := make([]*Record, 0)
	for _, rs := range rsb {
		records = append(records, rs.Flatten()...)
	}
	return records
}

// Get returns a record by type and id.
func (rsb RecordSetBundle) Get(typeName, id string) (record *Record, ok bool) {
	rs, ok := rsb[typeName]
	if !ok {
		return
	}
	record, ok = rs[id]
	return
}

// MarshalJSON marshals the record to JSON.
func (r *Record) MarshalJSON() ([]byte, error) {
	return protojson.Marshal(r)
}

// UnmarshalJSON unmarshals the record from JSON.
func (r *Record) UnmarshalJSON(data []byte) error {
	return protojson.Unmarshal(data, r)
}
