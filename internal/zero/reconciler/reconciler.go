package reconciler

import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Reconcile reconciles the target and current record sets with the databroker.
func Reconcile(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	target, current RecordSetBundle[DatabrokerRecord],
) error {
	updates := NewDatabrokerChangeSet()

	for _, rec := range current.GetRemoved(target).Flatten() {
		updates.Remove(rec.GetType(), rec.GetID())
	}
	for _, rec := range current.GetModified(target).Flatten() {
		updates.Upsert(rec.V)
	}
	for _, rec := range current.GetAdded(target).Flatten() {
		updates.Upsert(rec.V)
	}

	err := ApplyChanges(ctx, client, updates)
	if err != nil {
		return fmt.Errorf("apply databroker changes: %w", err)
	}

	return nil
}
