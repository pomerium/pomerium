package storage

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/google/uuid"
	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type staticQuerier struct {
	records map[string]RecordCollection
}

// NewStaticQuerier creates a Querier that returns statically defined protobuf records.
func NewStaticQuerier(msgs ...proto.Message) Querier {
	getter := &staticQuerier{records: make(map[string]RecordCollection)}
	for _, msg := range msgs {
		record, ok := msg.(*databroker.Record)
		if !ok {
			record = NewStaticRecord(protoutil.NewAny(msg).TypeUrl, msg)
		}
		c, ok := getter.records[record.Type]
		if !ok {
			c = NewRecordCollection()
			getter.records[record.Type] = c
		}
		c.Put(record)
	}
	return getter
}

// NewStaticRecord creates a new databroker Record from a protobuf message.
func NewStaticRecord(typeURL string, msg proto.Message) *databroker.Record {
	data := protoutil.NewAny(msg)
	record := new(databroker.Record)
	record.ModifiedAt = timestamppb.Now()
	record.Version = cryptutil.NewRandomUInt64()
	record.Id = uuid.New().String()
	record.Data = data
	record.Type = typeURL
	if hasID, ok := msg.(interface{ GetId() string }); ok {
		record.Id = hasID.GetId()
	}
	if hasVersion, ok := msg.(interface{ GetVersion() string }); ok {
		if v, err := strconv.ParseUint(hasVersion.GetVersion(), 10, 64); err == nil {
			record.Version = v
		}
	}

	var jsonData struct {
		ID      string `json:"id"`
		Version string `json:"version"`
	}
	bs, _ := protojson.Marshal(msg)
	_ = json.Unmarshal(bs, &jsonData)

	if jsonData.ID != "" {
		record.Id = jsonData.ID
	}
	if jsonData.Version != "" {
		if v, err := strconv.ParseUint(jsonData.Version, 10, 64); err == nil {
			record.Version = v
		}
	}

	return record
}

func (q *staticQuerier) InvalidateCache(_ context.Context, _ *databroker.QueryRequest) {}

// Query queries for records.
func (q *staticQuerier) Query(_ context.Context, req *databroker.QueryRequest, _ ...grpc.CallOption) (*databroker.QueryResponse, error) {
	return QueryRecordCollections(q.records, req)
}
