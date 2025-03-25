package databroker

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GetChangeSet returns list of changes between the current and target record sets,
// that may be applied to the databroker to bring it to the target state.
func GetChangeSet(current, target RecordSetBundle, cmpFn RecordCompareFn) []*Record {
	cs := &changeSet{now: timestamppb.Now()}

	for _, rec := range current.GetRemoved(target).Flatten() {
		cs.Remove(rec)
	}
	for _, rec := range current.GetModified(target, cmpFn).Flatten() {
		cs.Upsert(rec)
	}
	for _, rec := range current.GetAdded(target).Flatten() {
		cs.Upsert(rec)
	}

	return cs.updates
}

// changeSet is a set of databroker changes.
type changeSet struct {
	now     *timestamppb.Timestamp
	updates []*Record
}

// Remove adds a record to the change set.
func (cs *changeSet) Remove(record *Record) {
	record = proto.Clone(record).(*Record)
	record.DeletedAt = cs.now
	cs.updates = append(cs.updates, record)
}

// Upsert adds a record to the change set.
func (cs *changeSet) Upsert(record *Record) {
	cs.updates = append(cs.updates, &Record{
		Type: record.Type,
		Id:   record.Id,
		Data: record.Data,
	})
}

// PutMulti puts the records into the databroker in batches.
func PutMulti(ctx context.Context, client DataBrokerServiceClient, records ...*Record) error {
	if len(records) == 0 {
		return nil
	}

	updates := OptimumPutRequestsFromRecords(records)
	for _, req := range updates {
		_, err := client.Put(ctx, req)
		if err != nil {
			return fmt.Errorf("put databroker record: %w", err)
		}
	}
	return nil
}
