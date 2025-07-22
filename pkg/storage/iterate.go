package storage

import (
	"iter"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// A RecordIterator is an iterator over a sequence of records.
type RecordIterator iter.Seq2[*databroker.Record, error]

// RecordIteratorToList converts a RecordIterator into a list.
func RecordIteratorToList(seq RecordIterator) ([]*databroker.Record, error) {
	var records []*databroker.Record
	for record, err := range seq {
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, nil
}
