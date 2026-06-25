// Package databroker contains databroker protobuf definitions.
package databroker

import (
	"context"
	"fmt"
	"net/url"

	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	structpb "google.golang.org/protobuf/types/known/structpb"
)

//go:generate go tool go.uber.org/mock/mockgen -source=databroker_grpc.pb.go -destination ./mock_databroker/databroker.pb.go DataBrokerServiceClient
//go:generate go tool go.uber.org/mock/mockgen -source=leaser.go -destination ./mock_databroker/leaser.go LeaserHandler

type recordObject interface {
	proto.Message
	GetId() string
}

// NewRecord creates a new Record.
func NewRecord(object recordObject) *Record {
	return &Record{
		Type: getTypeURL(object),
		Id:   object.GetId(),
		Data: newAny(object),
	}
}

// IsNotFound returns true if the error is a not found error.
func IsNotFound(err error) bool {
	return status.Code(err) == codes.NotFound
}

// Get gets a record from the databroker and unmarshals it into the object.
func Get(ctx context.Context, client DataBrokerServiceClient, object recordObject) error {
	res, err := client.Get(ctx, &GetRequest{
		Type: getTypeURL(object),
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

// CompositeRecordID builds a deterministic record ID from key-value pairs
// using URL query string encoding. Keys are sorted alphabetically to ensure
// consistent output regardless of map iteration order.
func CompositeRecordID(m map[string]any) string {
	v := make(url.Values, len(m))
	for key, val := range m {
		v.Set(key, fmt.Sprint(val))
	}
	return v.Encode()
}

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

func getTypeURL(msg proto.Message) string {
	// taken from the anypb package
	return "type.googleapis.com/" + string(msg.ProtoReflect().Descriptor().FullName())
}

func newAny(src proto.Message) *anypb.Any {
	a, err := anypb.New(src)
	if err != nil {
		panic(err)
	}
	return a
}
