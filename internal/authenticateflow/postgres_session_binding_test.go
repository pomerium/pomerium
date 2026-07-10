package authenticateflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/postgresidentity"
	"github.com/pomerium/pomerium/internal/testutil/matchers"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestCreatePostgresSessionBinding(t *testing.T) {
	now := time.Now()
	webSession := &session.Session{
		Id:        "session-id",
		UserId:    "user-id",
		IdpId:     "idp-id",
		ExpiresAt: timestamppb.New(now.Add(30 * time.Minute)),
	}
	h := &session.Handle{
		Id:                 webSession.Id,
		UserId:             webSession.UserId,
		IdentityProviderId: webSession.IdpId,
	}

	ctrl := gomock.NewController(t)
	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	flow := &Stateful{dataBrokerClient: client}
	client.EXPECT().Get(t.Context(), matchers.ProtoEq(&databroker.GetRequest{
		Type: grpcutil.GetTypeURL(new(session.Session)),
		Id:   webSession.Id,
	})).Return(&databroker.GetResponse{Record: &databroker.Record{
		Type: grpcutil.GetTypeURL(webSession),
		Id:   webSession.Id,
		Data: protoutil.NewAny(webSession),
	}}, nil)
	client.EXPECT().Put(t.Context(), gomock.Any()).DoAndReturn(func(_ context.Context, request *databroker.PutRequest, _ ...grpc.CallOption) (*databroker.PutResponse, error) {
		require.Len(t, request.GetRecords(), 1)
		require.Equal(t, "postgrescert-SHA256:test", request.GetRecords()[0].GetId())
		var binding session.SessionBinding
		require.NoError(t, request.GetRecords()[0].GetData().UnmarshalTo(&binding))
		require.Equal(t, session.ProtocolPostgres, binding.GetProtocol())
		require.Equal(t, webSession.Id, binding.GetSessionId())
		require.Equal(t, webSession.UserId, binding.GetUserId())
		require.Equal(t, "db.example.com", binding.GetDetails()[postgresidentity.DetailRouteHostname])
		require.WithinDuration(t, webSession.GetExpiresAt().AsTime(), binding.GetExpiresAt().AsTime(), time.Second)
		return &databroker.PutResponse{}, nil
	})

	binding, err := flow.CreatePostgresSessionBinding(
		t.Context(), h, "idp-id", "postgrescert-SHA256:test", "db.example.com", now.Add(45*time.Minute))
	require.NoError(t, err)
	require.WithinDuration(t, webSession.GetExpiresAt().AsTime(), binding.GetExpiresAt().AsTime(), time.Second)
}

func TestCreatePostgresSessionBindingRejectsSessionMismatch(t *testing.T) {
	webSession := &session.Session{
		Id:        "session-id",
		UserId:    "different-user",
		IdpId:     "idp-id",
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}
	ctrl := gomock.NewController(t)
	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	flow := &Stateful{dataBrokerClient: client}
	client.EXPECT().Get(t.Context(), gomock.Any()).Return(&databroker.GetResponse{Record: &databroker.Record{
		Data: protoutil.NewAny(webSession),
	}}, nil)

	_, err := flow.CreatePostgresSessionBinding(t.Context(), &session.Handle{
		Id:                 "session-id",
		UserId:             "user-id",
		IdentityProviderId: "idp-id",
	}, "idp-id", "postgrescert-SHA256:test", "db.example.com", time.Now().Add(time.Hour))
	require.ErrorIs(t, err, ErrPostgresSessionBindingInvalidSession)
}

func TestStatelessCreatePostgresSessionBindingUnsupported(t *testing.T) {
	_, err := new(Stateless).CreatePostgresSessionBinding(
		t.Context(), new(session.Handle), "idp", "binding", "db.example.com", time.Now().Add(time.Hour))
	require.True(t, errors.Is(err, ErrPostgresSessionBindingUnsupported))
}

func TestPostgresSessionBindingExpiry(t *testing.T) {
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name    string
		cert    time.Time
		session *timestamppb.Timestamp
		want    time.Time
	}{
		{"certificate", now.Add(20 * time.Minute), timestamppb.New(now.Add(30 * time.Minute)), now.Add(20 * time.Minute)},
		{"session", now.Add(40 * time.Minute), timestamppb.New(now.Add(30 * time.Minute)), now.Add(30 * time.Minute)},
		{"one hour", now.Add(2 * time.Hour), timestamppb.New(now.Add(3 * time.Hour)), now.Add(time.Hour)},
		{"missing session expiry", now.Add(2 * time.Hour), nil, now.Add(time.Hour)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, postgresSessionBindingExpiry(now, tc.cert, tc.session))
		})
	}
}
