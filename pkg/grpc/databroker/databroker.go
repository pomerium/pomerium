// Package databroker contains databroker protobuf definitions.
package databroker

import (
	"context"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"

	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

//go:generate go run github.com/golang/mock/mockgen -source=databroker.pb.go -destination ./mock_databroker/databroker.pb.go DataBrokerServiceClient
//go:generate go run github.com/golang/mock/mockgen -source=leaser.go -destination ./mock_databroker/leaser.go LeaserHandler

type recordObject interface {
	proto.Message
	GetId() string
}

// NewRecord creates a new Record.
func NewRecord(object recordObject) *Record {
	return &Record{
		Type: grpcutil.GetTypeURL(object),
		Id:   object.GetId(),
		Data: protoutil.NewAny(object),
	}
}

// Get gets a record from the databroker and unmarshals it into the object.
func Get(ctx context.Context, client DataBrokerServiceClient, object recordObject) error {
	res, err := client.Get(ctx, &GetRequest{
		Type: grpcutil.GetTypeURL(object),
		Id:   object.GetId(),
	})
	if err != nil {
		return err
	}

	return res.GetRecord().GetData().UnmarshalTo(object)
}

// Put puts a record into the databroker.
func Put(ctx context.Context, client DataBrokerServiceClient, object recordObject) (*PutResponse, error) {
	return client.Put(ctx, &PutRequest{Record: NewRecord(object)})
}

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
