package legacymanager

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity/identity"
	metrics_ids "github.com/pomerium/pomerium/pkg/metrics"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type mockAuthenticator struct {
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

func TestManager_refresh(t *testing.T) {
	ctrl := gomock.NewController(t)
	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	t.Cleanup(clearTimeout)

	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	mgr := New(WithDataBrokerClient(client))
	mgr.onUpdateRecords(ctx, updateRecordsMessage{
		records: []*databroker.Record{
			databroker.NewRecord(&session.Session{
				Id:         "s1",
				UserId:     "u1",
				OauthToken: &session.OAuthToken{},
				ExpiresAt:  timestamppb.New(time.Now().Add(time.Second * 10)),
			}),
			databroker.NewRecord(&user.User{
				Id: "u1",
			}),
		},
	})
	client.EXPECT().Get(gomock.Any(), gomock.Any()).Return(nil, status.Error(codes.NotFound, "not found"))
	mgr.refreshSession(ctx, "u1", "s1")
	mgr.refreshUser(ctx, "u1")
}

func TestManager_onUpdateRecords(t *testing.T) {
	ctrl := gomock.NewController(t)

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	now := time.Now()

	mgr := New(
		WithDataBrokerClient(mock_databroker.NewMockDataBrokerServiceClient(ctrl)),
		WithNow(func() time.Time {
			return now
		}),
	)

	mgr.onUpdateRecords(ctx, updateRecordsMessage{
		records: []*databroker.Record{
			mkRecord(&session.Session{Id: "session1", UserId: "user1"}),
			mkRecord(&user.User{Id: "user1", Name: "user 1", Email: "user1@example.com"}),
		},
	})

	if _, ok := mgr.sessions.Get("user1", "session1"); assert.True(t, ok) {
		tm, id := mgr.sessionScheduler.Next()
		assert.Equal(t, now.Add(10*time.Second), tm)
		assert.Equal(t, "user1\037session1", id)
	}
	if _, ok := mgr.users.Get("user1"); assert.True(t, ok) {
		tm, id := mgr.userScheduler.Next()
		assert.Equal(t, now.Add(userRefreshInterval), tm)
		assert.Equal(t, "user1", id)
	}
}

func TestManager_onUpdateSession(t *testing.T) {
	startTime := time.Date(2023, 10, 19, 12, 0, 0, 0, time.UTC)

	s := &session.Session{
		Id:     "session-id",
		UserId: "user-id",
		OauthToken: &session.OAuthToken{
			AccessToken: "access-token",
			ExpiresAt:   timestamppb.New(startTime.Add(5 * time.Minute)),
		},
		IssuedAt:  timestamppb.New(startTime),
		ExpiresAt: timestamppb.New(startTime.Add(24 * time.Hour)),
	}

	assertNextScheduled := func(t *testing.T, mgr *Manager, expectedTime time.Time) {
		t.Helper()
		tm, key := mgr.sessionScheduler.Next()
		assert.Equal(t, expectedTime, tm)
		assert.Equal(t, "user-id\037session-id", key)
	}

	t.Run("initial refresh event when not expiring soon", func(t *testing.T) {
		now := startTime
		mgr := New(WithNow(func() time.Time { return now }))

		// When the Manager first becomes aware of a session it should schedule
		// a refresh event for one minute before access token expiration.
		mgr.onUpdateSession(mkRecord(s), s)
		assertNextScheduled(t, mgr, startTime.Add(4*time.Minute))
	})
	t.Run("initial refresh event when expiring soon", func(t *testing.T) {
		now := startTime
		mgr := New(WithNow(func() time.Time { return now }))

		// When the Manager first becomes aware of a session, if that session
		// is expiring within the gracePeriod (1 minute), it should schedule a
		// refresh event for as soon as possible, subject to the
		// coolOffDuration (10 seconds).
		now = now.Add(4*time.Minute + 30*time.Second) // 30 s before expiration
		mgr.onUpdateSession(mkRecord(s), s)
		assertNextScheduled(t, mgr, now.Add(10*time.Second))
	})
	t.Run("update near scheduled refresh", func(t *testing.T) {
		now := startTime
		mgr := New(WithNow(func() time.Time { return now }))

		mgr.onUpdateSession(mkRecord(s), s)
		assertNextScheduled(t, mgr, startTime.Add(4*time.Minute))

		// If a session is updated close to the time when it is scheduled to be
		// refreshed, the scheduled refresh event should not be pushed back.
		now = now.Add(3*time.Minute + 55*time.Second) // 5 s before refresh
		mgr.onUpdateSession(mkRecord(s), s)
		assertNextScheduled(t, mgr, now.Add(5*time.Second))

		// However, if an update changes the access token validity, the refresh
		// event should be rescheduled accordingly. (This should be uncommon,
		// as only the refresh loop itself should modify the access token.)
		s2 := proto.Clone(s).(*session.Session)
		s2.OauthToken.ExpiresAt = timestamppb.New(now.Add(5 * time.Minute))
		mgr.onUpdateSession(mkRecord(s2), s2)
		assertNextScheduled(t, mgr, now.Add(4*time.Minute))
	})
	t.Run("session record deleted", func(t *testing.T) {
		now := startTime
		mgr := New(WithNow(func() time.Time { return now }))

		mgr.onUpdateSession(mkRecord(s), s)
		assertNextScheduled(t, mgr, startTime.Add(4*time.Minute))

		// If a session is deleted, any scheduled refresh event should be canceled.
		record := mkRecord(s)
		record.DeletedAt = timestamppb.New(now)
		mgr.onUpdateSession(record, s)
		_, key := mgr.sessionScheduler.Next()
		assert.Empty(t, key)
	})
}

func TestManager_refreshSession(t *testing.T) {
	startTime := time.Date(2023, 10, 19, 12, 0, 0, 0, time.UTC)

	var auth mockAuthenticator

	ctrl := gomock.NewController(t)
	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

	now := startTime
	mgr := New(
		WithDataBrokerClient(client),
		WithNow(func() time.Time { return now }),
		WithAuthenticator(&auth),
	)

	// Initialize the Manager with a new session.
	s := &session.Session{
		Id:     "session-id",
		UserId: "user-id",
		OauthToken: &session.OAuthToken{
			AccessToken:  "access-token",
			ExpiresAt:    timestamppb.New(startTime.Add(5 * time.Minute)),
			RefreshToken: "refresh-token",
		},
		IssuedAt:  timestamppb.New(startTime),
		ExpiresAt: timestamppb.New(startTime.Add(24 * time.Hour)),
	}
	mgr.sessions.ReplaceOrInsert(Session{
		Session:         s,
		lastRefresh:     startTime,
		gracePeriod:     time.Minute,
		coolOffDuration: 10 * time.Second,
	})

	// If OAuth2 token refresh fails with a temporary error, the manager should
	// still reschedule another refresh attempt.
	now = now.Add(4 * time.Minute)
	auth.refreshError = context.DeadlineExceeded
	mgr.refreshSession(context.Background(), "user-id", "session-id")

	tm, key := mgr.sessionScheduler.Next()
	assert.Equal(t, now.Add(10*time.Second), tm)
	assert.Equal(t, "user-id\037session-id", key)

	// Simulate a successful token refresh on the second attempt. The manager
	// should store the updated session in the databroker and schedule another
	// refresh event.
	now = now.Add(10 * time.Second)
	auth.refreshResult, auth.refreshError = &oauth2.Token{
		AccessToken:  "new-access-token",
		RefreshToken: "new-refresh-token",
		Expiry:       now.Add(5 * time.Minute),
	}, nil
	expectedSession := proto.Clone(s).(*session.Session)
	expectedSession.OauthToken = &session.OAuthToken{
		AccessToken:  "new-access-token",
		ExpiresAt:    timestamppb.New(now.Add(5 * time.Minute)),
		RefreshToken: "new-refresh-token",
	}
	client.EXPECT().Patch(gomock.Any(), objectsAreEqualMatcher{
		&databroker.PatchRequest{
			Records: []*databroker.Record{{
				Type: "type.googleapis.com/session.Session",
				Id:   "session-id",
				Data: protoutil.NewAny(expectedSession),
			}},
			FieldMask: &fieldmaskpb.FieldMask{
				Paths: []string{"oauth_token", "id_token", "claims"},
			},
		},
	}).
		Return(nil /* this result is currently unused */, nil)
	mgr.refreshSession(context.Background(), "user-id", "session-id")

	tm, key = mgr.sessionScheduler.Next()
	assert.Equal(t, now.Add(4*time.Minute), tm)
	assert.Equal(t, "user-id\037session-id", key)
}

func TestManager_reportErrors(t *testing.T) {
	ctrl := gomock.NewController(t)

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	evtMgr := events.New()
	received := make(chan events.Event, 1)
	handle := evtMgr.Register(func(evt events.Event) {
		received <- evt
	})
	defer evtMgr.Unregister(handle)

	expectMsg := func(id, msg string) {
		t.Helper()
		assert.Eventually(t, func() bool {
			select {
			case evt := <-received:
				lastErr := evt.(*events.LastError)
				return msg == lastErr.Message && id == lastErr.Id
			default:
				return false
			}
		}, time.Second, time.Millisecond*20, msg)
	}

	s := &session.Session{
		Id:     "session1",
		UserId: "user1",
		OauthToken: &session.OAuthToken{
			ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
		},
		ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
	}

	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	client.EXPECT().Get(gomock.Any(), gomock.Any()).AnyTimes().Return(&databroker.GetResponse{Record: databroker.NewRecord(s)}, nil)
	client.EXPECT().Put(gomock.Any(), gomock.Any()).AnyTimes()
	mgr := New(
		WithEventManager(evtMgr),
		WithDataBrokerClient(client),
		WithAuthenticator(&mockAuthenticator{
			refreshError:        errors.New("update session"),
			updateUserInfoError: errors.New("update user info"),
		}),
	)

	mgr.onUpdateRecords(ctx, updateRecordsMessage{
		records: []*databroker.Record{
			mkRecord(s),
			mkRecord(&user.User{Id: "user1", Name: "user 1", Email: "user1@example.com"}),
		},
	})

	mgr.refreshUser(ctx, "user1")
	expectMsg(metrics_ids.IdentityManagerLastUserRefreshError, "update user info")

	mgr.onUpdateRecords(ctx, updateRecordsMessage{
		records: []*databroker.Record{
			mkRecord(s),
			mkRecord(&user.User{Id: "user1", Name: "user 1", Email: "user1@example.com"}),
		},
	})

	mgr.refreshSession(ctx, "user1", "session1")
	expectMsg(metrics_ids.IdentityManagerLastSessionRefreshError, "update session")
}

func mkRecord(msg recordable) *databroker.Record {
	data := protoutil.NewAny(msg)
	return &databroker.Record{
		Type: data.GetTypeUrl(),
		Id:   msg.GetId(),
		Data: data,
	}
}

type recordable interface {
	proto.Message
	GetId() string
}

// objectsAreEqualMatcher implements gomock.Matcher using ObjectsAreEqual. This
// is especially helpful when working with pointers, as it will compare the
// underlying values rather than the pointers themselves.
type objectsAreEqualMatcher struct {
	expected interface{}
}

func (m objectsAreEqualMatcher) Matches(x interface{}) bool {
	return assert.ObjectsAreEqual(m.expected, x)
}

func (m objectsAreEqualMatcher) String() string {
	return fmt.Sprintf("is equal to %v (%T)", m.expected, m.expected)
}
