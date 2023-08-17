package reconciler

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// DatabrokerChangeSet is a set of databroker changes.
type DatabrokerChangeSet struct {
	now     *timestamppb.Timestamp
	updates []*databroker.Record
}

// NewDatabrokerChangeSet creates a new databroker change set.
func NewDatabrokerChangeSet() *DatabrokerChangeSet {
	return &DatabrokerChangeSet{
		now: timestamppb.Now(),
	}
}

// Remove adds a record to the change set.
func (cs *DatabrokerChangeSet) Remove(typ string, id string) {
	cs.updates = append(cs.updates, &databroker.Record{
		Type:      typ,
		Id:        id,
		DeletedAt: cs.now,
	})
}

// Upsert adds a record to the change set.
func (cs *DatabrokerChangeSet) Upsert(record *databroker.Record) {
	cs.updates = append(cs.updates, &databroker.Record{
		Type: record.Type,
		Id:   record.Id,
		Data: record.Data,
	})
}

// ApplyChanges applies the changes to the databroker.
func ApplyChanges(ctx context.Context, client databroker.DataBrokerServiceClient, changes *DatabrokerChangeSet) error {
	updates := databroker.OptimumPutRequestsFromRecords(changes.updates)
	for _, req := range updates {
		_, err := client.Put(ctx, req)
		if err != nil {
			return fmt.Errorf("put databroker record: %w", err)
		}
	}
	return nil
}
