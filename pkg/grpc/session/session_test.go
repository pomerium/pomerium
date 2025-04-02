package session

import (
	context "context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestDelete(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

	ctx := context.Background()
	rpcErr := status.Error(codes.Unavailable, "dummy error for testing")

	client.EXPECT().Put(ctx, gomock.Any(), []grpc.CallOption{}).DoAndReturn(
		func(_ context.Context, r *databroker.PutRequest, _ ...grpc.CallOption) (*databroker.PutResponse, error) {
			require.Len(t, r.Records, 1)
			record := r.GetRecord()
			assert.Equal(t, "type.googleapis.com/session.Session", record.Type)
			assert.Equal(t, "session-id", record.Id)
			testutil.AssertProtoEqual(t, protoutil.NewAny(&Session{}), record.Data)
			now := time.Now()
			assert.WithinRange(t, record.DeletedAt.AsTime(), now.Add(-time.Minute), now)
			return nil, rpcErr
		})

	err := Delete(ctx, client, "session-id")
	assert.Same(t, rpcErr, err)
}

func TestGet(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("ok", func(t *testing.T) {
		t.Parallel()

		session := &Session{
			Id:     "session-id",
			UserId: "user-id",
		}
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().Get(ctx, gomock.Any(), []grpc.CallOption{}).DoAndReturn(
			func(_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
				assert.Equal(t, "type.googleapis.com/session.Session", r.Type)
				assert.Equal(t, "session-id", r.Id)
				return &databroker.GetResponse{Record: &databroker.Record{
					Data: protoutil.NewAny(session),
				}}, nil
			})
		s, err := Get(ctx, client, "session-id")
		assert.NoError(t, err)
		testutil.AssertProtoEqual(t, session, s)
	})

	t.Run("rpc error", func(t *testing.T) {
		t.Parallel()

		rpcErr := status.Error(codes.Unavailable, "dummy error for testing")
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().Get(ctx, gomock.Any(), []grpc.CallOption{}).DoAndReturn(
			func(_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
				assert.Equal(t, "type.googleapis.com/session.Session", r.Type)
				assert.Equal(t, "session-id", r.Id)
				return nil, rpcErr
			})
		s, err := Get(ctx, client, "session-id")
		assert.Nil(t, s)
		assert.Same(t, rpcErr, err)
	})

	t.Run("unmarshal error", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().Get(ctx, gomock.Any(), []grpc.CallOption{}).DoAndReturn(
			func(_ context.Context, r *databroker.GetRequest, _ ...grpc.CallOption) (*databroker.GetResponse, error) {
				assert.Equal(t, "type.googleapis.com/session.Session", r.Type)
				assert.Equal(t, "session-id", r.Id)
				return &databroker.GetResponse{}, nil // no record
			})
		s, err := Get(ctx, client, "session-id")
		assert.Nil(t, s)
		assert.ErrorContains(t, err, "error unmarshaling session from databroker")
	})
}

func TestPut(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

	ctx := context.Background()

	dummyPutResponse := &databroker.PutResponse{}
	rpcErr := status.Error(codes.Unavailable, "dummy error for testing")

	session := &Session{
		Id:     "session-id",
		UserId: "user-id",
	}

	client.EXPECT().Put(ctx, gomock.Any(), []grpc.CallOption{}).DoAndReturn(
		func(_ context.Context, r *databroker.PutRequest, _ ...grpc.CallOption) (*databroker.PutResponse, error) {
			require.Len(t, r.Records, 1)
			record := r.GetRecord()
			assert.Equal(t, "type.googleapis.com/session.Session", record.Type)
			assert.Equal(t, "session-id", record.Id)
			testutil.AssertProtoEqual(t, protoutil.NewAny(session), record.Data)
			return dummyPutResponse, rpcErr
		})

	r, err := Put(ctx, client, session)
	assert.Same(t, dummyPutResponse, r)
	assert.Same(t, rpcErr, err)
}

func TestPatch(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

	ctx := context.Background()

	dummyFieldMask := &fieldmaskpb.FieldMask{}
	dummyPatchResponse := &databroker.PatchResponse{}
	rpcErr := status.Error(codes.Unavailable, "dummy error for testing")

	session := &Session{
		Id:     "session-id",
		UserId: "user-id",
	}

	client.EXPECT().Patch(ctx, gomock.Any(), []grpc.CallOption{}).DoAndReturn(
		func(_ context.Context, r *databroker.PatchRequest, _ ...grpc.CallOption) (*databroker.PatchResponse, error) {
			require.Len(t, r.Records, 1)
			record := r.Records[0]
			assert.Equal(t, "type.googleapis.com/session.Session", record.Type)
			assert.Equal(t, "session-id", record.Id)
			testutil.AssertProtoEqual(t, protoutil.NewAny(session), record.Data)
			assert.Same(t, dummyFieldMask, r.FieldMask)
			return dummyPatchResponse, rpcErr
		})

	r, err := Patch(ctx, client, session, dummyFieldMask)
	assert.Same(t, dummyPatchResponse, r)
	assert.Same(t, rpcErr, err)
}

func TestSession_Validate(t *testing.T) {
	t.Parallel()

	t0 := timestamppb.New(time.Now().Add(-time.Second))
	for _, tc := range []struct {
		name    string
		session *Session
		expect  error
	}{
		{"valid", &Session{}, nil},
		{"expired", &Session{ExpiresAt: t0}, ErrSessionExpired},
		{"expired oauth token", &Session{OauthToken: &OAuthToken{ExpiresAt: t0}}, ErrSessionExpired},
		// Expiry of the ID token does not indicate expiry of the underlying session.
		{"expired id token ok", &Session{IdToken: &IDToken{ExpiresAt: t0}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.ErrorIs(t, tc.session.Validate(), tc.expect)
		})
	}
}

func TestParseIDToken(t *testing.T) {
	t.Parallel()

	// The empty string should parse as a nil IDToken.
	parsed, err := ParseIDToken("")
	require.NoError(t, err)
	require.Nil(t, parsed)

	// Exercise error handling for malformed ID tokens.
	parsed, err = ParseIDToken("not a valid JWT")
	require.Nil(t, parsed)
	require.ErrorContains(t, err, "compact JWS format must have three parts")
	parsed, err = ParseIDToken("e30.ImZvbyI.e30")
	require.Nil(t, parsed)
	require.ErrorContains(t, err, "cannot unmarshal string")

	// Create a token with a representative set of claims.
	claimsMap := map[string]any{
		"iss":            "https://idp.example.com",
		"aud":            "client-1234.idp.example.com",
		"sub":            "user_1122334455",
		"email":          "john.doe@example.com",
		"email_verified": true,
		"name":           "John Doe",
		"iat":            1720800000,
		"exp":            1720803600,
	}
	claimsJSON, err := json.Marshal(claimsMap)
	require.NoError(t, err)

	// Attach a dummy header and signature (these aren't validated) to form an example token.
	idToken := "e30." + base64.RawURLEncoding.EncodeToString(claimsJSON) + ".e30"

	parsed, err = ParseIDToken(idToken)
	assert.NoError(t, err)
	testutil.AssertProtoEqual(t, &IDToken{
		Issuer:    "https://idp.example.com",
		Subject:   "user_1122334455",
		IssuedAt:  &timestamppb.Timestamp{Seconds: 1720800000},
		ExpiresAt: &timestamppb.Timestamp{Seconds: 1720803600},
		Raw:       idToken,
	}, parsed)
}
