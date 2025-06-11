package databroker_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
	grpc "google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func Test_SyncLatestRecords(t *testing.T) {
	t.Parallel()

	ctx, clearTimeout := context.WithTimeout(t.Context(), time.Minute)
	defer clearTimeout()

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, databroker.New(ctx, trace.NewNoopTracerProvider()))
	})

	c := databrokerpb.NewDataBrokerServiceClient(cc)

	expected := []*user.User{
		{Id: "u1"},
		{Id: "u2"},
		{Id: "u3"},
	}

	for _, u := range expected {
		_, err := c.Put(ctx, &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{
				databrokerpb.NewRecord(u),
			},
		})
		require.NoError(t, err)
	}

	// add a non-user record to make sure it gets ignored
	_, err := c.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{
			{
				Id:   "u4",
				Type: protoutil.GetTypeURL(new(user.User)),
				Data: protoutil.NewAny(&session.Session{Id: "s1"}),
			},
		},
	})
	require.NoError(t, err)

	var actual []*user.User
	serverVersion, latestRecordVersion, err := databrokerpb.SyncLatestRecords(t.Context(), c, func(u *user.User) {
		actual = append(actual, u)
	})
	assert.NoError(t, err)
	assert.NotZero(t, serverVersion)
	assert.Equal(t, uint64(4), latestRecordVersion)
	testutil.AssertProtoEqual(t, expected, actual)
}
