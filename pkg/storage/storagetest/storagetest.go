// Package storagetest contains test cases for use in verifying the behavior of
// a storage.Backend implementation.
package storagetest

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/storage"
)

// TestBackendPatch verifies the behavior of the backend Patch() method.
func TestBackendPatch(t *testing.T, ctx context.Context, backend storage.Backend) { //nolint:revive
	mkRecord := func(s *session.Session) *databroker.Record {
		a, _ := anypb.New(s)
		return &databroker.Record{
			Type: a.TypeUrl,
			Id:   s.Id,
			Data: a,
		}
	}

	t.Run("basic", func(t *testing.T) {
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
		// Note: first truncate the modified_at timestamps to 1 µs precision, as
		// that is the maximum precision supported by Postgres.
		r1, _ := backend.Get(ctx, "type.googleapis.com/session.Session", "session-1")
		truncateTimestamps(updated[0].ModifiedAt, r1.ModifiedAt)
		testutil.AssertProtoEqual(t, updated[0], r1)
		r3, _ := backend.Get(ctx, "type.googleapis.com/session.Session", "session-3")
		truncateTimestamps(updated[1].ModifiedAt, r3.ModifiedAt)
		testutil.AssertProtoEqual(t, updated[1], r3)
	})

	t.Run("concurrent", func(t *testing.T) {
		if n := gomaxprocs(); n < 2 {
			t.Skipf("skipping concurrent test (GOMAXPROCS = %d)", n)
		}

		rs1 := make([]*databroker.Record, 1)
		rs2 := make([]*databroker.Record, 1)

		s1 := session.Session{Id: "concurrent", OauthToken: &session.OAuthToken{}}
		s2 := session.Session{Id: "concurrent", OauthToken: &session.OAuthToken{}}

		// Store an initial version of a session record.
		rs1[0] = mkRecord(&s1)
		_, err := backend.Put(ctx, rs1)
		require.NoError(t, err)

		fmAccessToken, err := fieldmaskpb.New(&session.Session{}, "oauth_token.access_token")
		require.NoError(t, err)
		fmRefreshToken, err := fieldmaskpb.New(&session.Session{}, "oauth_token.refresh_token")
		require.NoError(t, err)

		var wg sync.WaitGroup

		// Repeatedly make Patch calls to update the session from two separate
		// goroutines (one updating just the access token, the other updating
		// just the refresh token.) Verify that no updates are lost.
		for i := 0; i < 100; i++ {
			access := fmt.Sprintf("access-%d", i)
			s1.OauthToken.AccessToken = access
			rs1[0] = mkRecord(&s1)

			refresh := fmt.Sprintf("refresh-%d", i)
			s2.OauthToken.RefreshToken = refresh
			rs2[0] = mkRecord(&s2)

			wg.Add(2)
			go func() {
				_, _, _ = backend.Patch(ctx, rs1, fmAccessToken)
				wg.Done()
			}()
			go func() {
				_, _, _ = backend.Patch(ctx, rs2, fmRefreshToken)
				wg.Done()
			}()
			wg.Wait()

			r, err := backend.Get(ctx, "type.googleapis.com/session.Session", "concurrent")
			require.NoError(t, err)
			data, err := r.Data.UnmarshalNew()
			require.NoError(t, err)
			s := data.(*session.Session)
			require.Equal(t, access, s.OauthToken.AccessToken)
			require.Equal(t, refresh, s.OauthToken.RefreshToken)
		}
	})
}

// truncateTimestamps truncates Timestamp messages to 1 µs precision.
func truncateTimestamps(ts ...*timestamppb.Timestamp) {
	for _, t := range ts {
		t.Nanos = (t.Nanos / 1000) * 1000
	}
}

func gomaxprocs() int {
	env := os.Getenv("GOMAXPROCS")
	if n, err := strconv.Atoi(env); err == nil {
		return n
	}
	return runtime.NumCPU()
}
