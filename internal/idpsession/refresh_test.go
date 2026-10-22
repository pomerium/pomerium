package idpsession

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/identity"
)

func TestRefreshScheduler(t *testing.T) {
	t.Parallel()
	t.Run("shared sid", func(t *testing.T) {
		now := time.Now()
		authenticator := newMockAuthenticator(t)
		authenticator.EXPECT().
			Refresh(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				_ context.Context,
				token *oauth2.Token,
				_ identity.State,
			) (*oauth2.Token, error) {
				rotated := map[string]string{"foo": "baz", "bar": "qux"}[token.RefreshToken]
				return &oauth2.Token{
					AccessToken:  rotated,
					RefreshToken: rotated,
					TokenType:    "Bearer",
					Expiry:       now.Add(time.Hour),
				}, nil
			}).
			Times(1)

		authenticator.EXPECT().
			UpdateUserInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			Times(1)

		a := newIDPSession("id1", new("sid1"), "foo", now.Add(100*time.Millisecond))
		b := newIDPSession("id2", new("sid1"), "bar", now.Add(100*time.Millisecond))

		h := newSyncerReconcilerForTest(t, now, authenticator)
		h.put(
			databroker.NewRecord(&user.User{Id: "u1"}),
			databroker.NewRecord(a),
			databroker.NewRecord(b),
		)

		assertEventually(t, func(ct *assert.CollectT) {
			got1, ok := assertGetRecord(ct, h.client, &idpsession.IDPSession{Id: "id1"})
			if !ok {
				return
			}
			assert.Equal(ct, "baz", got1.GetOauthToken().GetAccessToken())
			got2, ok := assertGetRecord(ct, h.client, &idpsession.IDPSession{Id: "id2"})
			if !ok {
				return
			}
			assert.Equal(ct, "baz", got2.GetOauthToken().GetAccessToken())
		})
	})

	t.Run("no shared sid", func(t *testing.T) {
		now := time.Now()
		authenticator := newMockAuthenticator(t)
		authenticator.EXPECT().
			Refresh(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				_ context.Context,
				token *oauth2.Token,
				_ identity.State,
			) (*oauth2.Token, error) {
				rotated := map[string]string{"foo": "baz", "bar": "qux"}[token.RefreshToken]
				return &oauth2.Token{
					AccessToken:  rotated,
					RefreshToken: rotated,
					TokenType:    "Bearer",
					Expiry:       now.Add(time.Hour),
				}, nil
			}).
			Times(2)

		authenticator.EXPECT().
			UpdateUserInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			Times(2)

		a := newIDPSession("id1", nil, "foo", now.Add(100*time.Millisecond))
		b := newIDPSession("id2", nil, "bar", now.Add(100*time.Millisecond))

		h := newSyncerReconcilerForTest(t, now, authenticator)
		h.put(
			databroker.NewRecord(&user.User{Id: "u1"}),
			databroker.NewRecord(a),
			databroker.NewRecord(b),
		)

		assertEventually(t, func(ct *assert.CollectT) {
			got1, ok := assertGetRecord(ct, h.client, &idpsession.IDPSession{Id: "id1"})
			if !ok {
				return
			}
			assert.Equal(ct, "baz", got1.GetOauthToken().GetAccessToken())
			got2, ok := assertGetRecord(ct, h.client, &idpsession.IDPSession{Id: "id2"})
			if !ok {
				return
			}
			assert.Equal(ct, "qux", got2.GetOauthToken().GetAccessToken())
		})
	})

	t.Run("permanent refresh error", func(t *testing.T) {
		now := time.Now()
		authenticator := newMockAuthenticator(t)
		authenticator.EXPECT().
			Refresh(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(
				_ context.Context,
				token *oauth2.Token,
				_ identity.State,
			) (*oauth2.Token, error) {
				rotated := map[string]string{"foo": "baz"}[token.RefreshToken]
				if token.RefreshToken == "bar" {
					return nil, errors.New("invalid grant")
				}
				return &oauth2.Token{
					AccessToken:  rotated,
					RefreshToken: rotated,
					TokenType:    "Bearer",
					Expiry:       now.Add(time.Hour),
				}, nil
			}).
			Times(2)

		authenticator.EXPECT().
			UpdateUserInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			Times(1)

		a := newIDPSession("id1", nil, "foo", now.Add(100*time.Millisecond))
		b := newIDPSession("id2", nil, "bar", now.Add(100*time.Millisecond))

		h := newSyncerReconcilerForTest(t, now, authenticator)
		h.put(
			databroker.NewRecord(&user.User{Id: "u1"}),
			databroker.NewRecord(a),
			databroker.NewRecord(b),
		)

		assertEventually(t, func(ct *assert.CollectT) {
			got1, ok := assertGetRecord(ct, h.client, &idpsession.IDPSession{Id: "id1"})
			if !ok {
				return
			}
			assert.Equal(ct, "baz", got1.GetOauthToken().GetAccessToken())
			assertRecordDeleted(ct, h.client, idpSessionTypeURL, "id2")
		})
	})

	t.Run("user info no shared sid", func(t *testing.T) {
		now := time.Now()
		authenticator := newMockAuthenticator(t)
		authenticator.EXPECT().
			UpdateUserInfo(gomock.Any(), gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, token *oauth2.Token, dst any) error {
				tokenGroups := map[string][]byte{
					"foo": []byte(`{"groups":["g1"]}`),
					"bar": []byte(`{"groups":["g2"]}`),
				}[token.AccessToken]

				return json.Unmarshal(tokenGroups, dst)
			}).Times(2)

		h := newSyncerReconcilerForTest(t, now, authenticator)
		a := newIDPSession("id1", nil, "foo", now.Add(time.Hour))
		b := newIDPSession("id2", nil, "bar", now.Add(time.Hour))
		u := &user.User{Id: "u1"}
		a.Claims, _ = structpb.NewStruct(map[string]any{"amr": "mfa", "groups": []any{"g0"}})
		b.Claims, _ = structpb.NewStruct(map[string]any{"amr": "pwd", "groups": []any{"g0"}})
		h.put(databroker.NewRecord(a), databroker.NewRecord(b), databroker.NewRecord(u))

		assertEventually(t, func(ct *assert.CollectT) {
			assert.NotNil(ct, h.syncer.idx.GetUser("u1"))
		})

		h.syncer.refreshManager.updateUserInfo(t.Context(), "u1")

		for id, want := range map[string][2]any{"id1": {"mfa", []any{"g1"}}, "id2": {"pwd", []any{"g2"}}} {
			got, ok := assertGetRecord(t, h.client, &idpsession.IDPSession{Id: id})
			require.True(t, ok)
			assert.Equal(t, want[0], got.GetClaims().AsMap()["amr"])
			assert.Equal(t, want[1], got.GetClaims().AsMap()["groups"])
		}

		// not ideal, but same as previous behaviour.
		gotUser, ok := assertGetRecord(t, h.client, &user.User{Id: "u1"})
		require.True(t, ok)
		assert.Equal(t, map[string]*structpb.ListValue{"groups": {Values: []*structpb.Value{structpb.NewStringValue("g2")}}}, gotUser.GetClaims())
	})
}
