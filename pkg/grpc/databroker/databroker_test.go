package databroker

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestApplyOffsetAndLimit(t *testing.T) {
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
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	li, err := net.Listen("tcp", "127.0.0.1:0")
	if !assert.NoError(t, err) {
		return
	}
	defer li.Close()

	r1 := new(Record)
	r2 := new(Record)

	m := &mockServer{
		syncLatest: func(req *emptypb.Empty, stream DataBrokerService_SyncLatestServer) error {
			stream.Send(&SyncResponse{
				ServerVersion: 1,
				Record:        r1,
			})
			stream.Send(&SyncResponse{
				ServerVersion: 1,
				Record:        r2,
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

	records, serverVersion, err := InitialSync(ctx, c)
	assert.NoError(t, err)
	assert.Equal(t, uint64(1), serverVersion)
	assert.Equal(t, []*Record{r1, r2}, records)
}

type mockServer struct {
	DataBrokerServiceServer

	syncLatest func(empty *emptypb.Empty, server DataBrokerService_SyncLatestServer) error
}

func (m *mockServer) SyncLatest(req *emptypb.Empty, stream DataBrokerService_SyncLatestServer) error {
	return m.syncLatest(req, stream)
}
