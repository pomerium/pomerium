package idpsession

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestNewBoundRecords(t *testing.T) {
	records := NewBoundRecords(
		"upstream-session",
		BindingProtocol_BINDING_PROTOCOL_BROWSER,
		map[string]string{"user-agent": "test-browser/1.0"},
		&session.Session{Id: "session-id"},
	)
	require.Len(t, records, 2)

	assert.Equal(t, "type.googleapis.com/session.Session", records[0].GetType())
	assert.Equal(t, "session-id", records[0].GetId())

	var binding Binding
	require.NoError(t, records[1].GetData().UnmarshalTo(&binding))
	assert.Equal(t, "session-id", binding.GetId())
	assert.Equal(t, "type.googleapis.com/session.Session", binding.GetTypeUrl())
	assert.Equal(t, "upstream-session", binding.GetIdpSessionId())
	assert.Equal(t, BindingProtocol_BINDING_PROTOCOL_BROWSER, binding.GetProtocol())
	assert.Equal(t, "test-browser/1.0", binding.GetDetails()["user-agent"])
}

func TestGetIDPSession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	idpSessionID := "test-idp-session-id"
	idpSession := &IDPSession{
		Id:     idpSessionID,
		UserId: "test-user",
		IdpId:  "test-idp",
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

		client.EXPECT().Get(ctx, gomock.Any(), []grpc.CallOption{}).DoAndReturn(
			func(_ context.Context, req *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
				assert.Equal(t, protoutil.GetTypeURL(new(IDPSession)), req.Type)
				assert.Equal(t, idpSessionID, req.Id)
				return &databroker.GetResponse{
					Record: &databroker.Record{
						Data: protoutil.NewAny(idpSession),
					},
				}, nil
			})

		got, err := GetIDPSession(ctx, client, idpSessionID)
		assert.NoError(t, err)
		assert.Equal(t, idpSession.Id, got.Id)
		assert.Equal(t, idpSession.UserId, got.UserId)
		assert.Equal(t, idpSession.IdpId, got.IdpId)
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

		rpcErr := status.Error(codes.NotFound, "not found")
		client.EXPECT().Get(ctx, gomock.Any(), []grpc.CallOption{}).Return(nil, rpcErr)

		got, err := GetIDPSession(ctx, client, "nonexistent-id")
		assert.Nil(t, got)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}

func TestGetBinding(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	bindingID := "test-binding-id"
	binding := &Binding{
		Id:           bindingID,
		TypeUrl:      "type.googleapis.com/session.Session",
		IdpSessionId: "test-idp-session",
		Protocol:     BindingProtocol_BINDING_PROTOCOL_BROWSER,
	}

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

		client.EXPECT().Get(ctx, gomock.Any(), []grpc.CallOption{}).DoAndReturn(
			func(_ context.Context, req *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
				assert.Equal(t, protoutil.GetTypeURL(new(Binding)), req.Type)
				assert.Equal(t, bindingID, req.Id)
				return &databroker.GetResponse{
					Record: &databroker.Record{
						Data: protoutil.NewAny(binding),
					},
				}, nil
			})

		got, err := GetBinding(ctx, client, bindingID)
		assert.NoError(t, err)
		assert.Equal(t, binding.Id, got.Id)
		assert.Equal(t, binding.TypeUrl, got.TypeUrl)
		assert.Equal(t, binding.IdpSessionId, got.IdpSessionId)
		assert.Equal(t, binding.Protocol, got.Protocol)
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

		rpcErr := status.Error(codes.NotFound, "not found")
		client.EXPECT().Get(ctx, gomock.Any(), []grpc.CallOption{}).Return(nil, rpcErr)

		got, err := GetBinding(ctx, client, "nonexistent-id")
		assert.Nil(t, got)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}

func TestGetValidIDPSession(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	getReturning := func(t *testing.T, idpSess *IDPSession) databroker.DataBrokerServiceClient {
		client := mock_databroker.NewMockDataBrokerServiceClient(gomock.NewController(t))
		client.EXPECT().Get(ctx, gomock.Any(), []grpc.CallOption{}).Return(&databroker.GetResponse{
			Record: &databroker.Record{Data: protoutil.NewAny(idpSess)},
		}, nil)
		return client
	}

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		got, err := GetValidIDPSession(ctx, getReturning(t, &IDPSession{
			Id:    "user-1",
			State: &SessionState{State: UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_VALID},
		}), "user-1")
		assert.NoError(t, err)
		assert.Equal(t, "user-1", got.GetId())
	})

	t.Run("invalidated reads as not found", func(t *testing.T) {
		t.Parallel()
		got, err := GetValidIDPSession(ctx, getReturning(t, &IDPSession{
			Id: "user-1",
			State: &SessionState{
				State:   UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID,
				Details: "signed out",
			},
		}), "user-1")
		assert.Nil(t, got)
		assert.Equal(t, codes.NotFound, status.Code(err))
		assert.Contains(t, err.Error(), "signed out")
	})

	t.Run("expired copied access token is still valid", func(t *testing.T) {
		t.Parallel()
		got, err := GetValidIDPSession(ctx, getReturning(t, &IDPSession{
			Id:         "user-1",
			State:      &SessionState{State: UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_VALID},
			OauthToken: &OAuthToken{ExpiresAt: timestamppb.New(time.Now().Add(-time.Hour))},
		}), "user-1")
		assert.NoError(t, err)
		assert.NotNil(t, got)
	})
}

func TestGetActiveBinding(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	getReturning := func(t *testing.T, binding *Binding) databroker.DataBrokerServiceClient {
		client := mock_databroker.NewMockDataBrokerServiceClient(gomock.NewController(t))
		client.EXPECT().Get(ctx, gomock.Any(), []grpc.CallOption{}).Return(&databroker.GetResponse{
			Record: &databroker.Record{Data: protoutil.NewAny(binding)},
		}, nil)
		return client
	}

	t.Run("active", func(t *testing.T) {
		t.Parallel()
		got, err := GetActiveBinding(ctx, getReturning(t, &Binding{Id: "b1"}), "b1")
		assert.NoError(t, err)
		assert.Equal(t, "b1", got.GetId())
	})

	t.Run("revoked reads as not found", func(t *testing.T) {
		t.Parallel()
		got, err := GetActiveBinding(ctx, getReturning(t, &Binding{
			Id:    "b1",
			State: BindingState_BindingState_REVOKED,
		}), "b1")
		assert.Nil(t, got)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}
