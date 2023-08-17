package reconciler

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

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

// GetDatabrokerRecords gets all databroker records of the given types.
func GetDatabrokerRecords(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	types []string,
) (RecordSetBundle[DatabrokerRecord], error) {
	rsb := make(RecordSetBundle[DatabrokerRecord])

	for _, typ := range types {
		recs, err := getDatabrokerRecords(ctx, client, typ)
		if err != nil {
			return nil, fmt.Errorf("get databroker records for type %s: %w", typ, err)
		}
		rsb[typ] = recs
	}

	return rsb, nil
}

func getDatabrokerRecords(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	typ string,
) (RecordSet[DatabrokerRecord], error) {
	stream, err := client.SyncLatest(ctx, &databroker.SyncLatestRequest{Type: typ})
	if err != nil {
		return nil, fmt.Errorf("sync latest databroker: %w", err)
	}

	recordSet := make(RecordSet[DatabrokerRecord])
	for {
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
