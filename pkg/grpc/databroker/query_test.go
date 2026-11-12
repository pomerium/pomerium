package databroker_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestQueryAll(t *testing.T) {
	type testcase struct {
		pageSize        int
		total           int
		expectedPages   int
		expectedRecords int
	}

	tcs := []testcase{
		{
			pageSize:        0,
			total:           1000,
			expectedPages:   10,
			expectedRecords: 1000,
		},
		{
			pageSize:        0,
			total:           10000,
			expectedPages:   100,
			expectedRecords: 10000,
		},
		{
			pageSize:        200,
			total:           1000,
			expectedPages:   5,
			expectedRecords: 1000,
		},
	}

	for _, tc := range tcs {
		total := int64(tc.total)
		records := make([]*databroker.Record, total)
		for i := range records {
			records[i] = &databroker.Record{Id: fmt.Sprintf("s%d", i)}
		}
		client := mock_databroker.NewMockDataBrokerServiceClient(gomock.NewController(t))
		var pageSize int
		opts := []databroker.PaginationOption{}
		if tc.pageSize <= 0 {
			pageSize = 100
		} else {
			pageSize = tc.pageSize
			opts = append(opts, databroker.WithPageSize(tc.pageSize))
		}

		client.EXPECT().
			Query(gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, req *databroker.QueryRequest, _ ...grpc.CallOption) (*databroker.QueryResponse, error) {
				start := min(req.GetOffset(), total)
				end := min(start+req.GetLimit(), total)
				return &databroker.QueryResponse{
					ServerVersion: 1,
					Records:       records[start:end],
					TotalCount:    total,
				}, nil
			}).
			Times(tc.total / pageSize)

		recs := []*databroker.Record{}
		numPages := 0
		for page, err := range databroker.QueryAll(
			t.Context(), client, protoutil.GetTypeURL(new(session.Session)), &structpb.Struct{},
			opts...,
		) {
			require.NoError(t, err)
			assert.Equal(t, uint64(1), page.ServerVersion)
			assert.Equal(t, records[page.Offset:page.Offset+page.Limit], page.Records)
			recs = append(recs, page.Records...)
			numPages++
		}
		assert.Equal(t, tc.expectedRecords, len(recs))
		assert.Equal(t, tc.expectedPages, numPages)

	}

}
