package idpsession

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
	mock_identity "github.com/pomerium/pomerium/pkg/identity/mock_identity"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestRecordSetComparisonHelpers(t *testing.T) {
	want := make(databroker.RecordSetBundle)
	want.Add(databroker.NewRecord(&session.Session{Id: "session-1", UserId: "user-1"}))
	want.Add(databroker.NewRecord(&user.User{Id: "user-1", Email: "user@example.com"}))

	got := make(databroker.RecordSetBundle)
	got.Add(databroker.NewRecord(&user.User{Id: "user-1", Email: "user@example.com"}))
	got.Add(databroker.NewRecord(&session.Session{Id: "session-1", UserId: "user-1"}))

	requireRecordSetBundleEqual(t, want, got)
	requireRecordSetEqual(
		t,
		want["type.googleapis.com/session.Session"],
		got["type.googleapis.com/session.Session"],
	)
	assertRecordSetBundleEqual(t, want, got)
	assertRecordSetEqual(
		t,
		want["type.googleapis.com/session.Session"],
		got["type.googleapis.com/session.Session"],
	)

	different := make(databroker.RecordSetBundle)
	different.Add(databroker.NewRecord(&session.Session{Id: "session-1", UserId: "user-2"}))
	different.Add(databroker.NewRecord(&user.User{Id: "user-1", Email: "user@example.com"}))

	assertRecordSetBundleNotEqual(t, want, different)
	requireRecordSetBundleNotEqual(t, want, different)
	assertRecordSetNotEqual(
		t,
		want["type.googleapis.com/session.Session"],
		different["type.googleapis.com/session.Session"],
	)
	requireRecordSetNotEqual(
		t,
		want["type.googleapis.com/session.Session"],
		different["type.googleapis.com/session.Session"],
	)
}

func assertRecordSetEqual(t testing.TB, want, got databroker.RecordSet) {
	t.Helper()
	assert.Empty(t, recordSetDiff(want, got), "record sets differ (-want +got)")
}

func requireRecordSetEqual(t testing.TB, want, got databroker.RecordSet) {
	t.Helper()
	require.Empty(t, recordSetDiff(want, got), "record sets differ (-want +got)")
}

func assertRecordSetNotEqual(t testing.TB, want, got databroker.RecordSet) {
	t.Helper()
	assert.NotEmpty(t, recordSetDiff(want, got), "record sets unexpectedly match")
}

func requireRecordSetNotEqual(t testing.TB, want, got databroker.RecordSet) {
	t.Helper()
	require.NotEmpty(t, recordSetDiff(want, got), "record sets unexpectedly match")
}

func assertRecordSetBundleEqual(t testing.TB, want, got databroker.RecordSetBundle) {
	t.Helper()
	assert.Empty(t, recordSetBundleDiff(want, got), "record-set bundles differ (-want +got)")
}

func requireRecordSetBundleEqual(t testing.TB, want, got databroker.RecordSetBundle) {
	t.Helper()
	require.Empty(t, recordSetBundleDiff(want, got), "record-set bundles differ (-want +got)")
}

func assertRecordSetBundleNotEqual(t testing.TB, want, got databroker.RecordSetBundle) {
	t.Helper()
	assert.NotEmpty(t, recordSetBundleDiff(want, got), "record-set bundles unexpectedly match")
}

func requireRecordSetBundleNotEqual(t testing.TB, want, got databroker.RecordSetBundle) {
	t.Helper()
	require.NotEmpty(t, recordSetBundleDiff(want, got), "record-set bundles unexpectedly match")
}

func recordSetDiff(want, got databroker.RecordSet) string {
	return cmp.Diff(want, got, protocmp.Transform())
}

func recordSetBundleDiff(want, got databroker.RecordSetBundle) string {
	return cmp.Diff(want, got, protocmp.Transform())
}

type mockAuthenticator struct {
	identity.Authenticator

	refreshResult       *oauth2.Token
	refreshError        error
	revokeError         error
	updateUserInfoError error
}

func (mock *mockAuthenticator) Refresh(_ context.Context, _ *oauth2.Token, _ identity.State) (*oauth2.Token, error) {
	return mock.refreshResult, mock.refreshError
}

func (mock *mockAuthenticator) Revoke(_ context.Context, _ *oauth2.Token) error {
	return mock.revokeError
}

func (mock *mockAuthenticator) UpdateUserInfo(_ context.Context, _ *oauth2.Token, _ any) error {
	return mock.updateUserInfoError
}

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock(now time.Time) *testClock {
	return &testClock{now: now}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(duration time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(duration)
}

func boundRecords(now time.Time, idpSessionID string) []*databroker.Record {
	records := idpsession.NewBoundRecords(
		idpSessionID,
		"u1",
		idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER,
		nil,
		&session.Session{
			Id:        "s1",
			UserId:    "u1",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	)
	return append(records, idpsession.NewBoundRecords(
		idpSessionID,
		"u1",
		idpsession.BindingProtocol_BINDING_PROTOCOL_MCP,
		nil,
		&session.Session{
			Id:        "m1",
			UserId:    "u1",
			ExpiresAt: timestamppb.New(now.Add(time.Hour)),
		},
	)...)
}

func deletedRecord(message interface {
	proto.Message
	GetId() string
}, at time.Time,
) *databroker.Record {
	record := databroker.NewRecord(message)
	record.DeletedAt = timestamppb.New(at)
	return record
}

func assertGetRecord[T interface {
	proto.Message
	GetId() string
}](t assert.TestingT, client databroker.DataBrokerServiceClient, message T) (T, bool) {
	response, err := client.Get(context.Background(), &databroker.GetRequest{
		Type: protoutil.GetTypeURL(message),
		Id:   message.GetId(),
	})
	if !assert.NoError(t, err) {
		var zero T
		return zero, false
	}
	if !assert.NoError(t, response.GetRecord().GetData().UnmarshalTo(message)) {
		var zero T
		return zero, false
	}
	return message, true
}

func assertRecordExists(
	t assert.TestingT,
	client databroker.DataBrokerServiceClient,
	typeURL string,
	id string,
) {
	_, err := client.Get(context.Background(), &databroker.GetRequest{
		Type: typeURL,
		Id:   id,
	})
	assert.NoError(t, err, fmt.Sprintf("%s/%s", typeURL, id))
}

func assertRecordDeleted(
	t assert.TestingT,
	client databroker.DataBrokerServiceClient,
	typeURL string,
	id string,
) {
	_, err := client.Get(context.Background(), &databroker.GetRequest{
		Type: typeURL,
		Id:   id,
	})
	assert.Equal(t, codes.NotFound.String(), status.Code(err).String(), fmt.Sprintf("%s/%s", typeURL, id))
}

func assertDependentTokensEqual(
	t assert.TestingT,
	client databroker.DataBrokerServiceClient,
	want string,
) {
	browserSession, ok := assertGetRecord(t, client, &session.Session{Id: "s1"})
	if !ok {
		return
	}
	assert.Equal(t, want, browserSession.GetOauthToken().GetAccessToken())
	mcpSession, ok := assertGetRecord(t, client, &session.Session{Id: "m1"})
	if !ok {
		return
	}
	assert.Equal(t, want, mcpSession.GetOauthToken().GetAccessToken())
}

func assertEventually(t *testing.T, condition func(*assert.CollectT)) {
	t.Helper()
	assert.EventuallyWithT(t, condition, eventuallyTimeout, 10*time.Millisecond)
}

func newMockAuthenticator(t *testing.T) *mock_identity.MockAuthenticator {
	t.Helper()
	authenticator := mock_identity.NewMockAuthenticator(gomock.NewController(t))
	authenticator.EXPECT().Revoke(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
	return authenticator
}
