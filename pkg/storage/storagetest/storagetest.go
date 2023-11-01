package storagetest

import (
	"context"
	"testing"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// TODO: delete this type once Patch is added to the storage.Backend interface
type BackendWithPatch interface {
	storage.Backend
	Patch(context.Context, []*databroker.Record, *fieldmaskpb.FieldMask) (uint64, []*databroker.Record, error)
}

func TestBackendPatch(t *testing.T, ctx context.Context, backend BackendWithPatch) {
	mkRecord := func(s *session.Session) *databroker.Record {
		a, _ := anypb.New(s)
		return &databroker.Record{
			Type: a.TypeUrl,
			Id:   s.Id,
			Data: a,
		}
	}

	// Populate an initial set of session records.
	s1 := &session.Session{
		Id:         "session-1",
		IdToken:    &session.IDToken{Issuer: "issuer-1"},
		OauthToken: &session.OAuthToken{AccessToken: "access-token-1"},
	}
	s2 := &session.Session{
		Id:         "session-2",
		IdToken:    &session.IDToken{Issuer: "issuer-2"},
		OauthToken: &session.OAuthToken{AccessToken: "access-token-2"},
	}
	s3 := &session.Session{
		Id:         "session-3",
		IdToken:    &session.IDToken{Issuer: "issuer-3"},
		OauthToken: &session.OAuthToken{AccessToken: "access-token-3"},
	}
	initial := []*databroker.Record{mkRecord(s1), mkRecord(s2), mkRecord(s3)}

	_, err := backend.Put(ctx, initial)
	require.NoError(t, err)

	// Now patch just the oauth_token field.
	u1 := &session.Session{
		Id:         "session-1",
		OauthToken: &session.OAuthToken{AccessToken: "access-token-1-new"},
	}
	u2 := &session.Session{
		Id:         "session-4-does-not-exist",
		OauthToken: &session.OAuthToken{AccessToken: "access-token-4-new"},
	}
	u3 := &session.Session{
		Id:         "session-3",
		OauthToken: &session.OAuthToken{AccessToken: "access-token-3-new"},
	}

	mask, _ := fieldmaskpb.New(&session.Session{}, "oauth_token")

	_, updated, err := backend.Patch(
		ctx, []*databroker.Record{mkRecord(u1), mkRecord(u2), mkRecord(u3)}, mask)
	require.NoError(t, err)

	// The OAuthToken message should be updated but the IDToken message should
	// be unchanged, as it was not included in the field mask. The results
	// should indicate that only two records were updated (one did not exist).
	assert.Equal(t, 2, len(updated))
	assert.Greater(t, updated[0].Version, initial[0].Version)
	assert.Greater(t, updated[1].Version, initial[2].Version)
	testutil.AssertProtoJSONEqual(t, `{
		"@type": "type.googleapis.com/session.Session",
		"id": "session-1",
		"idToken": {
			"issuer": "issuer-1"
		},
		"oauthToken": {
			"accessToken": "access-token-1-new"
		}
	}`, updated[0].Data)
	testutil.AssertProtoJSONEqual(t, `{
		"@type": "type.googleapis.com/session.Session",
		"id": "session-3",
		"idToken": {
			"issuer": "issuer-3"
		},
		"oauthToken": {
			"accessToken": "access-token-3-new"
		}
	}`, updated[1].Data)

	// Verify that the updates will indeed be seen by a subsequent Get().
	r1, _ := backend.Get(ctx, "type.googleapis.com/session.Session", "session-1")
	testutil.AssertProtoEqual(t, updated[0], r1)
	r3, _ := backend.Get(ctx, "type.googleapis.com/session.Session", "session-3")
	testutil.AssertProtoEqual(t, updated[1], r3)
}
