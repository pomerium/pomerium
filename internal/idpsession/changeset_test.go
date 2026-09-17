package idpsession

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/pkg/databrokerutil/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type fakeClock struct {
	mu  sync.Mutex
	cur time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{
		cur: start,
	}
}

func (f *fakeClock) advance(dur time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cur = f.cur.Add(dur)
}

func (f *fakeClock) now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cur
}

func TestChangeSetApplier(t *testing.T) {
	ctx := t.Context()
	client := testutil.NewTestDatabroker(t)
	store := newChangeSetStore()
	applier := newChangeSetApplier(databroker.NewStaticClientGetter(client), store)
	start := time.Now()
	fakeClock := newFakeClock(start)

	idpSess1 := &idpsession.IDPSession{
		Id:         "foo1",
		RawIdToken: "id-token1",
		OauthToken: &idpsession.OAuthToken{
			AccessToken:  "accesstoken1",
			TokenType:    "Bearer",
			RefreshToken: "refresh1",
		},
	}

	idpSess2 := &idpsession.IDPSession{
		Id:         "foo2",
		RawIdToken: "id-token2",
		OauthToken: &idpsession.OAuthToken{
			AccessToken:  "accesstoken2",
			TokenType:    "Bearer",
			RefreshToken: "refresh2",
		},
	}

	setupRecords := []*databroker.Record{
		databroker.NewRecord(idpSess1),
		databroker.NewRecord(idpSess2),
	}

	for _, idPair := range [][2]string{
		{"foo1", "binding1"},
		{"foo1", "binding2"},
		{"foo2", "binding3"},
		{"foo2", "binding4"},
	} {
		setupRecords = append(setupRecords, idpsession.NewBoundRecords(
			idPair[0], idpsession.BindingProtocol_BINDING_PROTOCOL_BROWSER, map[string]string{}, &session.Session{Id: idPair[1]},
		)...)
	}

	// setup
	_, err := client.Put(ctx, &databroker.PutRequest{
		Records: setupRecords,
	})

	require.NoError(t, err)

	// bindings to foo1
	inputs := []input{
		{
			idpSession: idpSess1,
			delta:      -time.Minute,
		},
		{
			idpSession: idpSess2,
			delta:      -time.Minute,
		},
		{
			binding: &idpsession.Binding{
				Id:           "binding1",
				TypeUrl:      sessionTypeURL,
				IdpSessionId: "foo1",
			},
		},
		{
			binding: &idpsession.Binding{
				Id:           "binding2",
				IdpSessionId: "foo1",
				TypeUrl:      sessionTypeURL,
			},
		},
		{
			binding: &idpsession.Binding{
				Id:           "binding3",
				TypeUrl:      sessionTypeURL,
				IdpSessionId: "foo2",
			},
		},
		{
			binding: &idpsession.Binding{
				Id:           "binding4",
				TypeUrl:      sessionTypeURL,
				IdpSessionId: "foo2",
			},
		},
	}

	for _, entry := range inputs {
		if entry.binding != nil {
			applier.onUpdateBinding(ctx, entry.binding, start.Add(entry.delta))
		}
		if entry.idpSession != nil {
			applier.onUpdateIDPSession(ctx, entry.idpSession, start.Add(entry.delta))
		}
	}

	// propagate idpsession fields to bindings
	require.NoError(t, applier.ReconcileAtLocked(ctx, fakeClock.now()))

	bindingIDs1 := []string{"binding1", "binding2"}
	bindingIDs2 := []string{"binding3", "binding4"}
	for _, id := range bindingIDs1 {
		got, err := client.Get(ctx, &databroker.GetRequest{
			Type: sessionTypeURL,
			Id:   id,
		})
		require.NoError(t, err)

		sess := &session.Session{}
		require.NoError(t, got.GetRecord().GetData().UnmarshalTo(sess))

		assert.Equal(t, sess.OauthToken.AccessToken, "accesstoken1")
		assert.Equal(t, sess.OauthToken.TokenType, "Bearer")
		assert.Equal(t, sess.OauthToken.RefreshToken, "refresh1")
	}

	for _, id := range bindingIDs2 {
		got, err := client.Get(ctx, &databroker.GetRequest{
			Type: sessionTypeURL,
			Id:   id,
		})
		require.NoError(t, err)

		sess := &session.Session{}
		require.NoError(t, got.GetRecord().GetData().UnmarshalTo(sess))

		assert.Equal(t, sess.OauthToken.AccessToken, "accesstoken2")
		assert.Equal(t, sess.OauthToken.TokenType, "Bearer")
		assert.Equal(t, sess.OauthToken.RefreshToken, "refresh2")
	}

	// propagate a revoked binding
	revoked := &idpsession.Binding{
		Id:           "binding3",
		TypeUrl:      sessionTypeURL,
		IdpSessionId: "foo2",
		State:        idpsession.BindingState_BindingState_REVOKED,
	}
	_, revokeErr := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{databroker.NewRecord(revoked)},
	})
	require.NoError(t, revokeErr)

	applier.onUpdateBinding(ctx, revoked, start.Add(time.Minute))

	fakeClock.advance(time.Minute)

	require.NoError(t, applier.ReconcileAtLocked(ctx, fakeClock.now()))

	_, getErr := client.Get(ctx, &databroker.GetRequest{
		Type: sessionTypeURL,
		Id:   "binding3",
	})
	assert.Error(t, getErr)
	assert.Equal(t, codes.NotFound, status.Code(getErr))

	// the other way around -> an expired (and deleted) session should mark the binding revoked
	sess4Deleted := databroker.NewRecord(&session.Session{Id: "binding4"})
	sess4Deleted.DeletedAt = timestamppb.Now()

	_, delErr := client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{sess4Deleted},
	})
	require.NoError(t, delErr)

	applier.scheduleRevokeBinding(ctx, sess4Deleted.Id, fakeClock.now())

	applier.ReconcileAtLocked(ctx, fakeClock.now())

	updateBinding, err := client.Get(ctx, &databroker.GetRequest{
		Type: bindingTypeURL,
		Id:   "binding4",
	})
	require.NoError(t, err)
	b := &idpsession.Binding{}
	require.NoError(t, updateBinding.GetRecord().GetData().UnmarshalTo(b))
	assert.Equal(t, idpsession.BindingState_BindingState_REVOKED, b.State)

	applier.onUpdateIDPSession(ctx, &idpsession.IDPSession{
		Id: "foo1",
		State: &idpsession.SessionState{
			State: idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID,
		},
	}, fakeClock.now())

	applier.onUpdateIDPSession(ctx, &idpsession.IDPSession{
		Id: "foo2",
		State: &idpsession.SessionState{
			State: idpsession.UpstreamIdPSessionState_UPSTREAM_IDP_SESSION_STATE_INVALID,
		},
	}, fakeClock.now())

	fakeClock.advance(time.Minute * 4)

	require.NoError(t, applier.ReconcileAtLocked(ctx, fakeClock.now()))

	for _, id := range append(bindingIDs1, bindingIDs2...) {
		_, err := client.Get(ctx, &databroker.GetRequest{
			Type: sessionTypeURL,
			Id:   id,
		})
		assert.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))

		got, err := client.Get(ctx, &databroker.GetRequest{
			Type: bindingTypeURL,
			Id:   id,
		})
		require.NoError(t, err)
		b := &idpsession.Binding{}
		require.NoError(t, got.GetRecord().GetData().UnmarshalTo(b))
		assert.Equal(t, idpsession.BindingState_BindingState_REVOKED, b.State, b.Id)
	}
}

type input struct {
	delta      time.Duration
	idpSession *idpsession.IDPSession
	binding    *idpsession.Binding
}
