// Package databroker contains databroker protobuf definitions.
package databroker

import (
	"context"
	"errors"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	structpb "google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

//go:generate go run go.uber.org/mock/mockgen -source=databroker_grpc.pb.go -destination ./mock_databroker/databroker.pb.go DataBrokerServiceClient
//go:generate go run go.uber.org/mock/mockgen -source=leaser.go -destination ./mock_databroker/leaser.go LeaserHandler

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
func Put(ctx context.Context, client DataBrokerServiceClient, objects ...recordObject) (*PutResponse, error) {
	records := make([]*Record, len(objects))
	for i, object := range objects {
		records[i] = NewRecord(object)
	}
	return client.Put(ctx, &PutRequest{Records: records})
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
		case errors.Is(err, io.EOF):
			break loop
		case err != nil:
			return nil, 0, 0, fmt.Errorf("error receiving record: %w", err)
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

// GetRecord gets the first record, or nil if there are none.
func (x *PutRequest) GetRecord() *Record {
	records := x.GetRecords()
	if len(records) == 0 {
		return nil
	}
	return records[0]
}

// GetRecord gets the first record, or nil if there are none.
func (x *PutResponse) GetRecord() *Record {
	records := x.GetRecords()
	if len(records) == 0 {
		return nil
	}
	return records[0]
}

// GetRecord gets the first record, or nil if there are none.
func (x *PatchResponse) GetRecord() *Record {
	records := x.GetRecords()
	if len(records) == 0 {
		return nil
	}
	return records[0]
}

// SetFilterByID sets the filter to an id.
func (x *QueryRequest) SetFilterByID(id string) {
	x.Filter = &structpb.Struct{Fields: map[string]*structpb.Value{
		"id": structpb.NewStringValue(id),
	}}
}

// SetFilterByIDOrIndex sets the filter to an id or an index.
func (x *QueryRequest) SetFilterByIDOrIndex(idOrIndex string) {
	x.Filter = &structpb.Struct{Fields: map[string]*structpb.Value{
		"$or": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
			structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
				"id": structpb.NewStringValue(idOrIndex),
			}}),
			structpb.NewStructValue(&structpb.Struct{Fields: map[string]*structpb.Value{
				"$index": structpb.NewStringValue(idOrIndex),
			}}),
		}}),
	}}
}

// default is 4MB, but we'll do 1MB
const maxMessageSize = 1024 * 1024 * 1

// OptimumPutRequestsFromRecords creates one or more PutRequests from a slice of records.
// If the size of the request exceeds the max message size it will be split in half
// recursively until the requests are less than or equal to the max message size.
func OptimumPutRequestsFromRecords(records []*Record) []*PutRequest {
	if len(records) <= 1 {
		return []*PutRequest{{Records: records}}
	}

	req := &PutRequest{
		Records: records,
	}
	if proto.Size(req) <= maxMessageSize {
		return []*PutRequest{req}
	}

	return append(
		OptimumPutRequestsFromRecords(records[:len(records)/2]),
		OptimumPutRequestsFromRecords(records[len(records)/2:])...,
	)
}
