package code_test

import (
	"maps"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/slices"
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

func reducePairs(t *testing.T, pairs map[string]*code.IdentitySessionPair) []proto.Message {
	t.Helper()
	toCmp := []proto.Message{}
	for id := range iterutil.SortedUnion(strings.Compare, maps.Keys(pairs)) {
		pair := pairs[id]
		require.NotNil(t, pair.SB)
		toCmp = append(toCmp, pair.SB)
		if pair.IB != nil {
			toCmp = append(toCmp, pair.IB)
		}
	}
	return toCmp
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

	s1 := &session.SessionBinding{
		UserId: "u1",
	}
	i1 := &session.IdentityBinding{
		UserId: "u1",
	}
	s2 := &session.SessionBinding{
		UserId: "u1",
	}
	s3 := &session.SessionBinding{
		UserId: "u2",
	}
	i3 := &session.IdentityBinding{
		UserId: "u2",
	}

	_, err = client.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{
			{
				Id:   "s1",
				Type: grpcutil.GetTypeURL(s1),
				Data: protoutil.NewAny(s1),
			},
			{
				Id:   "s2",
				Type: grpcutil.GetTypeURL(s2),
				Data: protoutil.NewAny(s2),
			},
			{
				Id:   "s3",
				Type: grpcutil.GetTypeURL(s3),
				Data: protoutil.NewAny(s3),
			},
			{
				Id:   "s1",
				Type: grpcutil.GetTypeURL(i1),
				Data: protoutil.NewAny(i1),
			},
			{
				Id:   "s3",
				Type: grpcutil.GetTypeURL(i3),
				Data: protoutil.NewAny(i3),
			},
		},
	})
	require.NoError(t, err)

	pairs, err := reader.GetSessionBindingsByUserID(t.Context(), "u1")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(pairs))

	assert.Empty(t, cmp.Diff(reducePairs(t, pairs), []proto.Message{
		s1,
		i1,
		s2,
	}, protocmp.Transform()))

	pairs2, err := reader.GetSessionBindingsByUserID(t.Context(), "u2")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(pairs2))
	assert.Empty(t, cmp.Diff(reducePairs(t, pairs2), []proto.Message{
		s3,
		i3,
	}, protocmp.Transform()))

	pairs3, err := reader.GetSessionBindingsByUserID(t.Context(), "u3")
	assert.NoError(t, err)
	assert.Equal(t, 0, len(pairs3))
}

func TestCodeRevoker(t *testing.T) {
	t.Parallel()

	client, clientB := initDatabrokerServer(t)
	revoker := code.NewRevoker(clientB)

	err := revoker.RevokeCode(t.Context(), code.CodeID("c1"))
	assert.NoError(t, err)

	err = revoker.RevokeIdentityBinding(t.Context(), code.BindingID("s1"))
	assert.NoError(t, err)

	err = revoker.RevokeSessionBinding(t.Context(), code.BindingID("s1"))
	assert.NoError(t, err)

	records, err := revoker.RevokeSessionBindingBySession(t.Context(), "session-1")
	assert.NoError(t, err)
	assert.Equal(t, 0, len(records))

	sbr := &session.SessionBindingRequest{}
	sb := &session.SessionBinding{}
	ib := &session.IdentityBinding{}

	_, err = client.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{
			{
				Id:   "c1",
				Type: grpcutil.GetTypeURL(sbr),
				Data: protoutil.NewAny(sbr),
			},
			{
				Id:   "s1",
				Type: grpcutil.GetTypeURL(sb),
				Data: protoutil.NewAny(sb),
			},
			{
				Id:   "s1",
				Type: grpcutil.GetTypeURL(ib),
				Data: protoutil.NewAny(ib),
			},
		},
	})

	require.NoError(t, err)

	resp, err := client.Get(t.Context(), &databrokerpb.GetRequest{
		Type: grpcutil.GetTypeURL(sbr),
		Id:   "c1",
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Record)

	resp, err = client.Get(t.Context(), &databrokerpb.GetRequest{
		Type: grpcutil.GetTypeURL(sb),
		Id:   "s1",
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Record)

	resp, err = client.Get(t.Context(), &databrokerpb.GetRequest{
		Type: grpcutil.GetTypeURL(ib),
		Id:   "s1",
	})
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.Record)

	err = revoker.RevokeCode(t.Context(), code.CodeID("c1"))
	assert.NoError(t, err)

	err = revoker.RevokeIdentityBinding(t.Context(), code.BindingID("s1"))
	assert.NoError(t, err)

	err = revoker.RevokeSessionBinding(t.Context(), code.BindingID("s1"))
	assert.NoError(t, err)

	resp, err = client.Get(t.Context(), &databrokerpb.GetRequest{
		Type: grpcutil.GetTypeURL(sbr),
		Id:   "c1",
	})
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())

	resp, err = client.Get(t.Context(), &databrokerpb.GetRequest{
		Type: grpcutil.GetTypeURL(sb),
		Id:   "s1",
	})
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok = status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())

	resp, err = client.Get(t.Context(), &databrokerpb.GetRequest{
		Type: grpcutil.GetTypeURL(ib),
		Id:   "s1",
	})
	assert.Error(t, err)
	assert.Nil(t, resp)
	st, ok = status.FromError(err)
	assert.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())

	s2 := &session.SessionBinding{
		SessionId: "session-1",
	}
	s3 := &session.SessionBinding{
		SessionId: "session-2",
	}
	s4 := &session.SessionBinding{
		SessionId: "session-1",
	}
	sess1Recs := []*databrokerpb.Record{
		{
			Id:   "s2",
			Type: grpcutil.GetTypeURL(s2),
			Data: protoutil.NewAny(s2),
		},
		{
			Id:   "s4",
			Type: grpcutil.GetTypeURL(s4),
			Data: protoutil.NewAny(s4),
		},
	}

	sess2Recs := []*databrokerpb.Record{
		{
			Id:   "s3",
			Type: grpcutil.GetTypeURL(s3),
			Data: protoutil.NewAny(s3),
		},
	}
	_, err = client.Put(t.Context(), &databrokerpb.PutRequest{
		Records: sess1Recs,
	})
	require.NoError(t, err)

	_, err = client.Put(t.Context(), &databrokerpb.PutRequest{
		Records: sess2Recs,
	})
	require.NoError(t, err)

	recs, err := revoker.RevokeSessionBindingBySession(t.Context(), "session-1")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(recs))
	recIDs := slices.Map(recs, func(rec *databrokerpb.Record) string {
		return rec.Id
	})
	sort.Strings(recIDs)
	assert.ElementsMatch(t, []string{"s2", "s4"}, recIDs)

	recs2, err := revoker.RevokeSessionBindingBySession(t.Context(), "session-2")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(recs2))
	recIDs2 := slices.Map(recs2, func(rec *databrokerpb.Record) string {
		return rec.Id
	})
	sort.Strings(recIDs2)
	assert.ElementsMatch(t, []string{"s3"}, recIDs2)
}
