package manager

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/directory"
	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/identity/identity"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	metrics_ids "github.com/pomerium/pomerium/pkg/metrics"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type mockProvider struct {
	user       func(ctx context.Context, userID, accessToken string) (*directory.User, error)
	userGroups func(ctx context.Context) ([]*directory.Group, []*directory.User, error)
}

func (mock mockProvider) User(ctx context.Context, userID, accessToken string) (*directory.User, error) {
	return mock.user(ctx, userID, accessToken)
}

func (mock mockProvider) UserGroups(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
	return mock.userGroups(ctx)
}

type mockAuthenticator struct{}

func (mock mockAuthenticator) Refresh(_ context.Context, _ *oauth2.Token, _ identity.State) (*oauth2.Token, error) {
	return nil, errors.New("update session")
}

func (mock mockAuthenticator) Revoke(_ context.Context, _ *oauth2.Token) error {
	return errors.New("not implemented")
}

func (mock mockAuthenticator) UpdateUserInfo(_ context.Context, _ *oauth2.Token, _ any) error {
	return errors.New("update user info")
}

func TestManager_onUpdateRecords(t *testing.T) {
	ctrl := gomock.NewController(t)

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	now := time.Now()

	mgr := New(
		WithDataBrokerClient(mock_databroker.NewMockDataBrokerServiceClient(ctrl)),
		WithDirectoryProvider(mockProvider{}),
		WithGroupRefreshInterval(time.Hour),
		WithNow(func() time.Time {
			return now
		}),
	)
	mgr.directoryBackoff.RandomizationFactor = 0 // disable randomization for deterministic testing

	mgr.onUpdateRecords(ctx, updateRecordsMessage{
		records: []*databroker.Record{
			mkRecord(&directory.Group{Id: "group1", Name: "group 1", Email: "group1@example.com"}),
			mkRecord(&directory.User{Id: "user1", DisplayName: "user 1", Email: "user1@example.com", GroupIds: []string{"group1s"}}),
			mkRecord(&session.Session{Id: "session1", UserId: "user1"}),
			mkRecord(&user.User{Id: "user1", Name: "user 1", Email: "user1@example.com"}),
		},
	})

	assert.NotNil(t, mgr.directoryGroups["group1"])
	assert.NotNil(t, mgr.directoryUsers["user1"])
	if _, ok := mgr.sessions.Get("user1", "session1"); assert.True(t, ok) {

	}
	if _, ok := mgr.users.Get("user1"); assert.True(t, ok) {
		tm, id := mgr.userScheduler.Next()
		assert.Equal(t, now.Add(time.Hour), tm)
		assert.Equal(t, "user1", id)
	}

}

func TestManager_refreshDirectoryUserGroups(t *testing.T) {
	ctrl := gomock.NewController(t)

	ctx, clearTimeout := context.WithTimeout(context.Background(), time.Second*10)
	defer clearTimeout()

	t.Run("backoff", func(t *testing.T) {
		cnt := 0
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().Put(gomock.Any(), gomock.Any()).AnyTimes()
		mgr := New(
			WithDataBrokerClient(client),
			WithDirectoryProvider(mockProvider{
				userGroups: func(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
					cnt++
					switch cnt {
					case 1:
						return nil, nil, fmt.Errorf("error 1")
					case 2:
						return nil, nil, fmt.Errorf("error 2")
					}
					return nil, nil, nil
				},
			}),
			WithGroupRefreshInterval(time.Hour),
		)
		mgr.directoryBackoff.RandomizationFactor = 0 // disable randomization for deterministic testing

		dur1 := mgr.refreshDirectoryUserGroups(ctx)
		dur2 := mgr.refreshDirectoryUserGroups(ctx)
		dur3 := mgr.refreshDirectoryUserGroups(ctx)

		assert.Greater(t, dur2, dur1)
		assert.Greater(t, dur3, dur2)
		assert.Equal(t, time.Hour, dur3)
	})
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

	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	client.EXPECT().Put(gomock.Any(), gomock.Any()).AnyTimes()
	mgr := New(
		WithEventManager(evtMgr),
		WithDataBrokerClient(client),
		WithAuthenticator(mockAuthenticator{}),
		WithDirectoryProvider(mockProvider{
			user: func(ctx context.Context, userID, accessToken string) (*directory.User, error) {
				return nil, fmt.Errorf("user")
			},
			userGroups: func(ctx context.Context) ([]*directory.Group, []*directory.User, error) {
				return nil, nil, fmt.Errorf("user groups")
			},
		}),
		WithGroupRefreshInterval(time.Second),
	)
	mgr.directoryBackoff.RandomizationFactor = 0 // disable randomization for deterministic testing

	mgr.onUpdateRecords(ctx, updateRecordsMessage{
		records: []*databroker.Record{
			mkRecord(&directory.Group{Id: "group1", Name: "group 1", Email: "group1@example.com"}),
			mkRecord(&directory.User{Id: "user1", DisplayName: "user 1", Email: "user1@example.com", GroupIds: []string{"group1s"}}),
			mkRecord(&session.Session{Id: "session1", UserId: "user1", OauthToken: &session.OAuthToken{
				ExpiresAt: timestamppb.New(time.Now().Add(time.Hour)),
			}, ExpiresAt: timestamppb.New(time.Now().Add(time.Hour))}),
			mkRecord(&user.User{Id: "user1", Name: "user 1", Email: "user1@example.com"}),
		},
	})

	_ = mgr.refreshDirectoryUserGroups(ctx)
	expectMsg(metrics_ids.IdentityManagerLastUserGroupRefreshError, "user groups")

	mgr.refreshUser(ctx, "user1")
	expectMsg(metrics_ids.IdentityManagerLastUserRefreshError, "update user info")

	mgr.refreshSession(ctx, "user1", "session1")
	expectMsg(metrics_ids.IdentityManagerLastSessionRefreshError, "update session")
}

func mkRecord(msg recordable) *databroker.Record {
	any := protoutil.NewAny(msg)
	return &databroker.Record{
		Type: any.GetTypeUrl(),
		Id:   msg.GetId(),
		Data: any,
	}
}

type recordable interface {
	proto.Message
	GetId() string
}
