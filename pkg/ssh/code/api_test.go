package code_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/ssh/code"
)

type wrapperGetter struct {
	client databrokerpb.DataBrokerServiceClient
}

var _ databrokerpb.ClientGetter = wrapperGetter{}

func (g wrapperGetter) GetDataBrokerServiceClient() databrokerpb.DataBrokerServiceClient {
	return g.client
}

func initDatabrokerServer(t *testing.T) (databrokerpb.DataBrokerServiceClient, databrokerpb.ClientGetter) {
	t.Helper()
	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		s.RegisterService(&databrokerpb.DataBrokerService_ServiceDesc, srv)
	})
	client := databrokerpb.NewDataBrokerServiceClient(cc)
	return client, wrapperGetter{client: client}
}

func TestCodeReader(t *testing.T) {
	t.Parallel()
	client, clientB := initDatabrokerServer(t)

	reader := code.NewReader(clientB)

	req, ok := reader.GetBindingRequest(t.Context(), code.CodeID("not-found"))
	assert.False(t, ok)
	assert.Nil(t, req)
	sbr := &session.SessionBindingRequest{}
	_, err := client.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{
			{
				Type: "type.googleapis.com/session.SessionBindingRequest",
				Id:   "not-found",
				Data: protoutil.NewAny(sbr),
			},
		},
	})
	require.NoError(t, err)

	br, ok := reader.GetBindingRequest(t.Context(), code.CodeID("not-found"))
	assert.True(t, ok)
	assert.Empty(t, cmp.Diff(sbr, br, protocmp.Transform()))
}

func TestCodeRevoker(t *testing.T) {
	t.Parallel()

	client, clientB := initDatabrokerServer(t)

	_, err := client.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{
			{
				Id:   "c1",
				Type: protoutil.GetTypeURL(new(session.SessionBindingRequest)),
				Data: protoutil.NewAny(&session.SessionBindingRequest{
					Key: "c1",
				}),
			},
		},
	})
	require.NoError(t, err)
	revoker := code.NewRevoker(clientB)

	err = revoker.RevokeCode(t.Context(), code.CodeID("c1"))
	assert.NoError(t, err)

	_, err = client.Get(t.Context(), &databrokerpb.GetRequest{
		Type: protoutil.GetTypeURL(new(session.SessionBindingRequest)),
		Id:   "c1",
	})

	assert.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}
