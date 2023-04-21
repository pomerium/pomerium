package manager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/identity/identity"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	metrics_ids "github.com/pomerium/pomerium/pkg/metrics"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

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
	}
	if _, ok := mgr.users.Get("user1"); assert.True(t, ok) {
		tm, id := mgr.userScheduler.Next()
		assert.Equal(t, now.Add(userRefreshInterval), tm)
		assert.Equal(t, "user1", id)
	}
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
		WithAuthenticator(mockAuthenticator{}),
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
