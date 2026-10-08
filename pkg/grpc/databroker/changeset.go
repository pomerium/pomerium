package databroker

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
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
// The records will be updated to the result of the Put call.
func PutMulti(ctx context.Context, client DataBrokerServiceClient, records ...*Record) error {
	if len(records) == 0 {
		return nil
	}

	updates := OptimumPutRequestsFromRecords(records)
	for _, req := range updates {
		res, err := client.Put(ctx, req)
		if err != nil {
			return fmt.Errorf("put databroker record: %w", err)
		}
		// update the original records
		if len(res.Records) == len(req.Records) {
			for i := range res.Records {
				*req.Records[i] = *proto.CloneOf(res.Records[i])
			}
		} else {
			log.Ctx(ctx).Error().Msg("databroker: result of put call returned an unexpected number of records")
		}
	}
	return nil
}
