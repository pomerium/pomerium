package reconciler

// RecordSetBundle is an index of databroker records by type
type RecordSetBundle[T Record[T]] map[string]RecordSet[T]

// RecordSet is an index of databroker records by their id.
type RecordSet[T Record[T]] map[string]T

// Record is a record
type Record[T any] interface {
	GetID() string
	GetType() string
	Equal(other T) bool
}

// RecordTypes returns the types of records in the bundle.
func (rsb RecordSetBundle[T]) RecordTypes() []string {
	types := make([]string, 0, len(rsb))
	for typ := range rsb {
		types = append(types, typ)
	}
	return types
}

// Add adds a record to the bundle.
func (rsb RecordSetBundle[T]) Add(record T) {
	rs, ok := rsb[record.GetType()]
	if !ok {
		rs = make(RecordSet[T])
		rsb[record.GetType()] = rs
	}
	rs[record.GetID()] = record
}

// GetAdded returns the records that are in other but not in rsb.
func (rsb RecordSetBundle[T]) GetAdded(other RecordSetBundle[T]) RecordSetBundle[T] {
	added := make(RecordSetBundle[T])
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
func (rsb RecordSetBundle[T]) GetRemoved(other RecordSetBundle[T]) RecordSetBundle[T] {
	return other.GetAdded(rsb)
}

// GetModified returns the records that are in both rs and other but have different data.
func (rsb RecordSetBundle[T]) GetModified(other RecordSetBundle[T]) RecordSetBundle[T] {
	modified := make(RecordSetBundle[T])
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
func (rs RecordSet[T]) GetAdded(other RecordSet[T]) RecordSet[T] {
	added := make(RecordSet[T])
	for id, record := range other {
		if _, ok := rs[id]; !ok {
			added[id] = record
		}
	}
	return added
}

// GetRemoved returns the records that are in rs but not in other.
func (rs RecordSet[T]) GetRemoved(other RecordSet[T]) RecordSet[T] {
	return other.GetAdded(rs)
}

// GetModified returns the records that are in both rs and other but have different data.
// by comparing the protobuf bytes of the payload.
func (rs RecordSet[T]) GetModified(other RecordSet[T]) RecordSet[T] {
	modified := make(RecordSet[T])
	for id, record := range other {
		otherRecord, ok := rs[id]
		if !ok {
			continue
		}

		if !record.Equal(otherRecord) {
			modified[id] = record
		}
	}
	return modified
}

// Flatten returns all records in the set.
func (rs RecordSet[T]) Flatten() []T {
	records := make([]T, 0, len(rs))
	for _, record := range rs {
		records = append(records, record)
	}
	return records
}

// Flatten returns all records in the bundle.
func (rsb RecordSetBundle[T]) Flatten() []T {
	records := make([]T, 0)
	for _, rs := range rsb {
		records = append(records, rs.Flatten()...)
	}
	return records
}

// Get returns a record by type and id.
func (rsb RecordSetBundle[T]) Get(typeName, id string) (record T, ok bool) {
	rs, ok := rsb[typeName]
	if !ok {
		return
	}
	record, ok = rs[id]
	return
}
