package databroker

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
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

type mockServer struct {
	DataBrokerServiceServer

	getAll func(context.Context, *GetAllRequest) (*GetAllResponse, error)
}

func (m *mockServer) GetAll(ctx context.Context, req *GetAllRequest) (*GetAllResponse, error) {
	return m.getAll(ctx, req)
}

func TestGetAllPages(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	t.Run("resource exhausted", func(t *testing.T) {
		li, err := net.Listen("tcp", "127.0.0.1:0")
		if !assert.NoError(t, err) {
			return
		}
		defer li.Close()

		m := &mockServer{
			getAll: func(ctx context.Context, req *GetAllRequest) (*GetAllResponse, error) {
				any, _ := anypb.New(wrapperspb.String("TEST"))
				var records []*Record
				for i := 0; i < 1000000; i++ {
					records = append(records, &Record{
						Type: req.GetType(),
						Data: any,
					})
				}
				return &GetAllResponse{Records: records}, nil
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

		res, err := GetAllPages(ctx, c, &GetAllRequest{
			Type: "TEST",
		})
		assert.Error(t, err)
		assert.Equal(t, codes.ResourceExhausted, status.Code(err))
		assert.Nil(t, res)
	})
	t.Run("with paging", func(t *testing.T) {
		li, err := net.Listen("tcp", "127.0.0.1:0")
		if !assert.NoError(t, err) {
			return
		}
		defer li.Close()

		m := &mockServer{
			getAll: func(ctx context.Context, req *GetAllRequest) (*GetAllResponse, error) {
				pageToken, _ := strconv.Atoi(req.GetPageToken())

				any, _ := anypb.New(wrapperspb.String("TEST"))
				var records []*Record
				for i := pageToken; i < pageToken+10000 && i < 1000000; i++ {
					records = append(records, &Record{
						Type: req.GetType(),
						Data: any,
					})
				}
				if len(records) == 0 {
					return &GetAllResponse{}, nil
				}
				return &GetAllResponse{Records: records, NextPageToken: strconv.Itoa(pageToken + 10000)}, nil
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

		res, err := GetAllPages(ctx, c, &GetAllRequest{
			Type: "TEST",
		})
		assert.NoError(t, err)
		assert.NotEqual(t, codes.ResourceExhausted, status.Code(err))
		assert.Len(t, res.GetRecords(), 1000000)
	})
}
