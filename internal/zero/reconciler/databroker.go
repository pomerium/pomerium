package reconciler

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// DatabrokerRecord is a wrapper around a databroker record.
type DatabrokerRecord struct {
	V *databroker.Record
}

var _ Record[DatabrokerRecord] = DatabrokerRecord{}

// GetID returns the databroker record's ID.
func (r DatabrokerRecord) GetID() string {
	return r.V.GetId()
}

// GetType returns the databroker record's type.
func (r DatabrokerRecord) GetType() string {
	return r.V.GetType()
}

// Equal returns true if the databroker records are equal.
func (r DatabrokerRecord) Equal(other DatabrokerRecord) bool {
	return r.V.Type == other.V.Type &&
		r.V.Id == other.V.Id &&
		proto.Equal(r.V.Data, other.V.Data)
}

// GetDataBrokerRecords gets all databroker records of the given types.
func (c *service) GetDatabrokerRecords(
	ctx context.Context,
	types []string,
) (RecordSetBundle[DatabrokerRecord], error) {
	rsb := make(RecordSetBundle[DatabrokerRecord])

	for _, typ := range types {
		recs, err := c.getDatabrokerRecords(ctx, typ)
		if err != nil {
			return nil, fmt.Errorf("get databroker records for type %s: %w", typ, err)
		}
		rsb[typ] = recs
	}

	return rsb, nil
}

func (c *service) getDatabrokerRecords(ctx context.Context, typ string) (RecordSet[DatabrokerRecord], error) {
	stream, err := c.config.databrokerClient.SyncLatest(ctx, &databroker.SyncLatestRequest{
		Type: typ,
	})
	if err != nil {
		return nil, fmt.Errorf("sync latest databroker: %w", err)
	}

	recordSet := make(RecordSet[DatabrokerRecord])
	for {
		err = c.databrokerRateLimit.Wait(ctx)
		if err != nil {
			return nil, fmt.Errorf("wait for databroker rate limit: %w", err)
		}

		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("receive databroker record: %w", err)
		}

		if record := res.GetRecord(); record != nil {
			recordSet[record.GetId()] = DatabrokerRecord{record}
		}
	}
	return recordSet, nil
}

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

func (c *service) ApplyChanges(ctx context.Context, changes *DatabrokerChangeSet) error {
	updates := databroker.OptimumPutRequestsFromRecords(changes.updates)
	for _, req := range updates {
		err := c.databrokerRateLimit.Wait(ctx)
		if err != nil {
			return fmt.Errorf("wait for databroker rate limit: %w", err)
		}
		_, err = c.config.databrokerClient.Put(ctx, req)
		if err != nil {
			return fmt.Errorf("put databroker record: %w", err)
		}
	}
	return nil
}

// PurgeRecordsNotInList removes databroker records that existed in
// the bundles, and were applied to the databroker, but no longer present in the bundle list.
func (c *service) PurgeRecordsNotInList(_ context.Context) error {
	// TODO: implement
	return nil
}
