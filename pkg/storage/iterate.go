package storage

import (
	"iter"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// A RecordIterator is an iterator over a sequence of records.
type RecordIterator = iter.Seq2[*databroker.Record, error]

const ControlFrameRecordType = "databroker.SyncConnect"

func ControlFrameRecord() databroker.Record {
	return databroker.Record{
		Type: ControlFrameRecordType,
	}
}
