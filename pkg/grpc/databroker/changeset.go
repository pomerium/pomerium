package databroker

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// ChangeSet is a set of databroker changes.
type ChangeSet struct {
	now     *timestamppb.Timestamp
	updates []*Record
}

// NewChangeSet creates a new databroker change set.
func NewChangeSet() *ChangeSet {
	return &ChangeSet{
		now: timestamppb.Now(),
	}
}

// Remove adds a record to the change set.
func (cs *ChangeSet) Remove(typ string, id string) {
	cs.updates = append(cs.updates, &Record{
		Type:      typ,
		Id:        id,
		DeletedAt: cs.now,
	})
}

// Upsert adds a record to the change set.
func (cs *ChangeSet) Upsert(record *Record) {
	cs.updates = append(cs.updates, &Record{
		Type: record.Type,
		Id:   record.Id,
		Data: record.Data,
	})
}

// ApplyChanges applies the changes to the databroker.
func ApplyChanges(ctx context.Context, client DataBrokerServiceClient, changes *ChangeSet) error {
	updates := OptimumPutRequestsFromRecords(changes.updates)
	for _, req := range updates {
		_, err := client.Put(ctx, req)
		if err != nil {
			return fmt.Errorf("put databroker record: %w", err)
		}
	}
	return nil
}
