package databroker

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
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
	r3 := new(Record)

	m := &mockServer{
		sync: func(req *SyncRequest, stream DataBrokerService_SyncServer) error {
			assert.Equal(t, true, req.GetNoWait())
			stream.Send(&SyncResponse{
				ServerVersion: "a",
				Records:       []*Record{r1, r2},
			})
			stream.Send(&SyncResponse{
				ServerVersion: "b",
				Records:       []*Record{r3},
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

	res, err := InitialSync(ctx, c, &SyncRequest{
		Type: "TEST",
	})
	assert.NoError(t, err)
	assert.Equal(t, "b", res.GetServerVersion())
	assert.Equal(t, []*Record{r1, r2, r3}, res.GetRecords())
}

type mockServer struct {
	DataBrokerServiceServer

	sync func(*SyncRequest, DataBrokerService_SyncServer) error
}

func (m *mockServer) Sync(req *SyncRequest, stream DataBrokerService_SyncServer) error {
	return m.sync(req, stream)
}
