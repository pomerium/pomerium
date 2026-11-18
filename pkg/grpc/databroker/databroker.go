// Package databroker contains databroker protobuf definitions.
package databroker

import (
	"context"
	"fmt"
	"net/url"

	"github.com/pomerium/pomerium/pkg/iterutil"
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

// PutIfMatchVersion writes records only if each record's Version is the version
// currently stored (0 for a record that must not exist yet). If any record was
// modified since it was read, nothing is written and the returned error
// satisfies IsRecordVersionMismatch.
func PutIfMatchVersion(ctx context.Context, client DataBrokerServiceClient, records ...*Record) (*PutResponse, error) {
	return client.Put(ctx, &PutRequest{Records: records, IfMatchVersion: new(true)})
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

const (
	defaultPageSize = 100
)

type paginationOptions struct {
	pageSize int64
}

func (o *paginationOptions) Apply(opts ...PaginationOption) {
	for _, opt := range opts {
		opt(o)
	}
}

type PaginationOption func(o *paginationOptions)

func WithPageSize(size int) PaginationOption {
	return func(o *paginationOptions) {
		o.pageSize = int64(size)
	}
}

func defaultPaginationOptions() *paginationOptions {
	return &paginationOptions{
		pageSize: defaultPageSize,
	}
}

// QueryAllIter queries all records of the given type matching filter,
// yielding one QueryPage per request. Default page size is 100.
// Deleted records are not filtered out and iteration stops after the first error.
func QueryAll(
	ctx context.Context,
	client DataBrokerServiceClient,
	typeURL string,
	filter *structpb.Struct,
	opts ...PaginationOption,
) iterutil.ErrorSeq[*QueryPage] {
	options := defaultPaginationOptions()
	options.Apply(opts...)
	return func(yield func(*QueryPage, error) bool) {
		limit := options.pageSize
		for offset := int64(0); ; offset += limit {
			resp, err := client.Query(ctx, &QueryRequest{
				Type:   typeURL,
				Offset: offset,
				Limit:  limit,
				Filter: filter,
			})
			if err != nil {
				_ = yield(nil, err)
				return
			}
			if !yield(&QueryPage{
				Offset:        offset,
				Limit:         limit,
				TotalCount:    resp.GetTotalCount(),
				Records:       resp.GetRecords(),
				ServerVersion: resp.ServerVersion,
				RecordVersion: resp.RecordVersion,
			}, nil) {
				return
			}

			if len(resp.GetRecords()) < int(limit) || offset+limit >= resp.GetTotalCount() {
				return
			}
		}
	}
}

// QueryPage is one page of results from a paginated QueryRequest.
type QueryPage struct {
	Offset        int64
	Limit         int64
	TotalCount    int64
	Records       []*Record
	ServerVersion uint64
	RecordVersion uint64
}
