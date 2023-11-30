package reconciler

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// EqualRecord returns true if the databroker records are equal.
func EqualRecord(a, b *databroker.Record) bool {
	return a.Type == b.Type &&
		a.Id == b.Id &&
		proto.Equal(a.Data, b.Data)
}

// GetDatabrokerRecords gets all databroker records of the given types.
func GetDatabrokerRecords(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	types []string,
) (databroker.RecordSetBundle, error) {
	rsb := make(databroker.RecordSetBundle)

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
) (databroker.RecordSet, error) {
	stream, err := client.SyncLatest(ctx, &databroker.SyncLatestRequest{Type: typ})
	if err != nil {
		return nil, fmt.Errorf("sync latest databroker: %w", err)
	}

	recordSet := make(databroker.RecordSet)
	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("receive databroker record: %w", err)
		}

		if record := res.GetRecord(); record != nil {
			recordSet[record.GetId()] = record
		}
	}
	return recordSet, nil
}
