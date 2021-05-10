// Package databroker contains databroker protobuf definitions.
package databroker

import (
	"context"
	"fmt"
	"io"
)

//go:generate go run github.com/golang/mock/mockgen -source=databroker.pb.go -destination ./mock_databroker/databroker.pb.go DataBrokerServiceClient
//go:generate go run github.com/golang/mock/mockgen -source=leaser.go -destination ./mock_databroker/leaser.go LeaserHandler

// ApplyOffsetAndLimit applies the offset and limit to the list of records.
func ApplyOffsetAndLimit(all []*Record, offset, limit int) (records []*Record, totalCount int) {
	records = all
	if offset < len(records) {
		records = records[offset:]
	} else {
		records = nil
	}
	if limit <= len(records) {
		records = records[:limit]
	}
	return records, len(all)
}

// InitialSync performs a sync latest and then returns all the results.
func InitialSync(
	ctx context.Context,
	client DataBrokerServiceClient,
	req *SyncLatestRequest,
) (records []*Record, recordVersion, serverVersion uint64, err error) {
	stream, err := client.SyncLatest(ctx, req)
	if err != nil {
		return nil, 0, 0, err
	}

loop:
	for {
		res, err := stream.Recv()
		switch {
		case err == io.EOF:
			break loop
		case err != nil:
			return nil, 0, 0, err
		}

		switch res := res.GetResponse().(type) {
		case *SyncLatestResponse_Versions:
			recordVersion = res.Versions.GetLatestRecordVersion()
			serverVersion = res.Versions.GetServerVersion()
		case *SyncLatestResponse_Record:
			records = append(records, res.Record)
		default:
			panic(fmt.Sprintf("unexpected response: %T", res))
		}
	}

	return records, recordVersion, serverVersion, nil
}
