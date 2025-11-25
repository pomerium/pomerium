package databroker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestApplyOffsetAndLimit(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		records       []*Record
		offset, limit int
		expect        []*Record
	}{
		{
			name:    "empty",
			records: nil,
			offset:  10,
			limit:   5,
			expect:  nil,
		},
		{
			name:    "less than limit",
			records: []*Record{{Id: "A"}, {Id: "B"}, {Id: "C"}, {Id: "D"}},
			offset:  1,
			limit:   10,
			expect:  []*Record{{Id: "B"}, {Id: "C"}, {Id: "D"}},
		},
		{
			name:    "more than limit",
			records: []*Record{{Id: "A"}, {Id: "B"}, {Id: "C"}, {Id: "D"}, {Id: "E"}, {Id: "F"}, {Id: "G"}, {Id: "H"}},
			offset:  3,
			limit:   2,
			expect:  []*Record{{Id: "D"}, {Id: "E"}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			actual, cnt := ApplyOffsetAndLimit(tc.records, tc.offset, tc.limit)
			assert.Equal(t, len(tc.records), cnt)
			assert.Equal(t, tc.expect, actual)
		})
	}
}

func TestInitialSync(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Second*10)
	defer clearTimeout()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer li.Close()

	r1 := new(Record)
	r2 := new(Record)

	o1 := new(TypedOptions)

	m := &mockServer{
		syncLatest: func(_ *SyncLatestRequest, stream DataBrokerService_SyncLatestServer) error {
			stream.Send(&SyncLatestResponse{
				Response: &SyncLatestResponse_Record{
					Record: r1,
				},
			})
			stream.Send(&SyncLatestResponse{
				Response: &SyncLatestResponse_Record{
					Record: r2,
				},
			})
			stream.Send(&SyncLatestResponse{
				Response: &SyncLatestResponse_Versions{
					Versions: &Versions{
						LatestRecordVersion: 2,
						ServerVersion:       1,
					},
				},
			})

			stream.Send(&SyncLatestResponse{
				Response: &SyncLatestResponse_Options{
					Options: o1,
				},
			})
			return nil
		},
	}

	srv := grpc.NewServer()
	RegisterDataBrokerServiceServer(srv, m)
	go srv.Serve(li)

	cc, err := grpc.Dial(li.Addr().String(), grpc.WithInsecure())
	if !assert.NoError(t, err) {
		return
	}
	defer cc.Close()

	c := NewDataBrokerServiceClient(cc)

	records, options, recordVersion, serverVersion, err := InitialSync(ctx, c, new(SyncLatestRequest))
	assert.NoError(t, err)
	assert.Equal(t, uint64(2), recordVersion)
	assert.Equal(t, uint64(1), serverVersion)
	testutil.AssertProtoEqual(t, []*Record{r1, r2}, records)
	testutil.AssertProtoEqual(t, []*TypedOptions{o1}, options)
}

func TestOptimumPutRequestsFromRecords(t *testing.T) {
	t.Parallel()

	var records []*Record
	for i := 0; i < 10_000; i++ {
		s := structpb.NewStructValue(&structpb.Struct{
			Fields: map[string]*structpb.Value{
				"long_string": structpb.NewStringValue(strings.Repeat("x", 987)),
			},
		})
		records = append(records, &Record{
			Id:   fmt.Sprintf("%d", i),
			Data: protoutil.NewAny(s),
		})
	}
	requests := OptimumPutRequestsFromRecords(records)
	for _, request := range requests {
		assert.LessOrEqual(t, proto.Size(request), maxMessageSize)
		assert.GreaterOrEqual(t, proto.Size(request), maxMessageSize/2)
	}
}

type mockServer struct {
	DataBrokerServiceServer

	syncLatest func(empty *SyncLatestRequest, server DataBrokerService_SyncLatestServer) error
}

func (m *mockServer) SyncLatest(req *SyncLatestRequest, stream DataBrokerService_SyncLatestServer) error {
	return m.syncLatest(req, stream)
}
