// Package storagetest contains test cases for use in verifying the behavior of
// a storage.Backend implementation.
package storagetest

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/registry"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

// TestBackendPatch verifies the behavior of the backend Patch() method.
func testBackendPatch(t *testing.T, ctx context.Context, backend storage.Backend) { //nolint:revive
	mkRecord := func(s *session.Session) *databroker.Record {
		a, _ := anypb.New(s)
		return &databroker.Record{
			Type: a.TypeUrl,
			Id:   s.Id,
			Data: a,
		}
	}

	t.Run("not found", func(t *testing.T) {
		mask, err := fieldmaskpb.New(&session.Session{}, "oauth_token")
		require.NoError(t, err)

		s := &session.Session{Id: "session-id-that-does-not-exist"}

		_, updated, err := backend.Patch(ctx, []*databroker.Record{mkRecord(s)}, mask)
		require.NoError(t, err)
		assert.Empty(t, updated)
	})

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
		if n := runtime.GOMAXPROCS(0); n < 2 {
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

func TestBackend(t *testing.T, backend storage.Backend) {
	t.Helper()

	ctx := t.Context()

	t.Run("get missing record", func(t *testing.T) {
		record, err := backend.Get(ctx, "TYPE", "abcd")
		require.Error(t, err)
		assert.Nil(t, record)
	})

	t.Run("put", func(t *testing.T) {
		serverVersion, err := backend.Put(ctx, []*databroker.Record{
			{Type: "test-1", Id: "r1", Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{
				"k1": protoutil.NewStructString("v1"),
			}))},
			{Type: "test-1", Id: "r2", Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{
				"k2": protoutil.NewStructString("v2"),
			}))},
		})
		assert.NotEqual(t, 0, serverVersion)
		assert.NoError(t, err)
	})

	t.Run("delete", func(t *testing.T) {
		serverVersion, err := backend.Put(ctx, []*databroker.Record{{
			Type:      "test-1",
			Id:        "r3",
			DeletedAt: timestamppb.Now(),
		}})
		assert.NotEqual(t, 0, serverVersion)
		assert.NoError(t, err)

		seq := backend.Sync(ctx, "test-1", serverVersion, 0, false)
		records, err := iterutil.CollectWithError(seq)
		require.NoError(t, err)
		assert.NotEmpty(t, records)
	})

	t.Run("capacity", func(t *testing.T) {
		err := backend.SetOptions(ctx, "capacity-test", &databroker.Options{
			Capacity: proto.Uint64(3),
		})
		require.NoError(t, err)

		for i := 0; i < 10; i++ {
			_, err = backend.Put(ctx, []*databroker.Record{{
				Type: "capacity-test",
				Id:   fmt.Sprint(i),
				Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{})),
			}})
			require.NoError(t, err)
		}

		_, _, seq, err := backend.SyncLatest(ctx, "capacity-test", nil)
		require.NoError(t, err)

		records, err := iterutil.CollectWithError(seq)
		require.NoError(t, err)
		assert.Len(t, records, 3)

		var ids []string
		for _, r := range records {
			ids = append(ids, r.GetId())
		}
		assert.Equal(t, []string{"7", "8", "9"}, ids, "should contain recent records")
	})

	t.Run("lease", func(t *testing.T) {
		acquired, err := backend.Lease(ctx, "lease-test", "client-1", time.Second)
		assert.NoError(t, err)
		assert.True(t, acquired)

		acquired, err = backend.Lease(ctx, "lease-test", "client-2", time.Second)
		assert.NoError(t, err)
		assert.False(t, acquired)
	})

	t.Run("latest", func(t *testing.T) {
		for i := 0; i < 100; i++ {
			_, err := backend.Put(ctx, []*databroker.Record{{
				Type: "latest-test",
				Id:   fmt.Sprint(i),
				Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{})),
			}})
			require.NoError(t, err)
		}

		_, _, seq, err := backend.SyncLatest(ctx, "latest-test", nil)
		require.NoError(t, err)

		count := map[string]int{}

		for record, err := range seq {
			assert.NoError(t, err)
			count[record.GetId()]++
		}
		assert.NoError(t, err)

		for i := 0; i < 100; i++ {
			assert.Equal(t, 1, count[fmt.Sprint(i)])
		}
	})

	t.Run("changed", func(t *testing.T) {
		ctx, clearTimeout := context.WithTimeout(ctx, 5*time.Second)
		defer clearTimeout()

		serverVersion, recordVersion, seq, err := backend.SyncLatest(ctx, "sync-test", nil)
		require.NoError(t, err)
		_, _ = iterutil.CollectWithError(seq)

		seq = backend.Sync(ctx, "", serverVersion, recordVersion, true)
		next, stop := iter.Pull2(seq)
		defer stop()

		go func() {
			for i := range 10 {
				_, err := backend.Put(ctx, []*databroker.Record{{
					Type: "sync-test",
					Id:   fmt.Sprint(i),
					Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{})),
				}})
				assert.NoError(t, err)
				time.Sleep(50 * time.Millisecond)
			}
		}()

		for i := range 10 {
			record, err, valid := next()
			assert.NoError(t, err)
			if assert.True(t, valid) {
				assert.Equal(t, fmt.Sprint(i), record.GetId())
				assert.Equal(t, "sync-test", record.GetType())
			} else {
				break
			}
		}
	})

	t.Run("list types", func(t *testing.T) {
		types, err := backend.ListTypes(ctx)
		assert.NoError(t, err)
		assert.Equal(t, []string{"capacity-test", "latest-test", "sync-test", "test-1"}, types)
	})

	t.Run("patch", func(t *testing.T) {
		testBackendPatch(t, ctx, backend)
	})

	t.Run("get record", func(t *testing.T) {
		data := new(anypb.Any)
		serverVersion, err := backend.Put(ctx, []*databroker.Record{
			{
				Type: "TYPE",
				Id:   "a",
				Data: data,
			},
			{
				Type: "TYPE",
				Id:   "b",
				Data: data,
			},
			{
				Type: "TYPE",
				Id:   "c",
				Data: data,
			},
		})
		assert.NoError(t, err)
		assert.NotZero(t, serverVersion)
		for _, id := range []string{"a", "b", "c"} {
			record, err := backend.Get(ctx, "TYPE", id)
			require.NoError(t, err)
			if assert.NotNil(t, record) {
				assert.Empty(t, cmp.Diff(data, record.Data, protocmp.Transform()))
				assert.Nil(t, record.DeletedAt)
				assert.Equal(t, id, record.Id)
				assert.NotNil(t, record.ModifiedAt)
				assert.Equal(t, "TYPE", record.Type)
			}
		}
	})

	t.Run("concurrency", func(t *testing.T) {
		eg, ctx := errgroup.WithContext(t.Context())
		eg.Go(func() error {
			for i := range 1000 {
				_, _ = backend.Get(ctx, "", fmt.Sprint(i))
			}
			return nil
		})
		eg.Go(func() error {
			for i := range 1000 {
				_, _ = backend.Put(ctx, []*databroker.Record{{
					Id: fmt.Sprint(i),
				}})
			}
			return nil
		})
		assert.NoError(t, eg.Wait())
	})

	t.Run("list types concurrent", func(t *testing.T) {
		ctx := t.Context()
		for i := range 10 {
			t := fmt.Sprintf("Type-%02d", i)
			go func() {
				_, _ = backend.Put(ctx, []*databroker.Record{{
					Id:   "1",
					Type: t,
				}})
			}()
			go func() {
				_, _ = backend.ListTypes(ctx)
			}()
		}
	})

	t.Run("close", func(t *testing.T) {
		t.Run("by context", func(t *testing.T) {
			ctx, cancel := context.WithCancel(ctx)

			serverVersion, recordVersion, seq, err := backend.SyncLatest(ctx, "", nil)
			require.NoError(t, err)
			_, err = iterutil.CollectWithError(seq)
			require.NoError(t, err)

			seq = backend.Sync(ctx, "", serverVersion, recordVersion, true)
			cancel()

			records, err := iterutil.CollectWithError(seq)
			assert.Len(t, records, 0)
			assert.ErrorIs(t, err, context.Canceled)
		})
		t.Run("by backend", func(t *testing.T) {
			serverVersion, recordVersion, seq, err := backend.SyncLatest(ctx, "", nil)
			require.NoError(t, err)
			_, err = iterutil.CollectWithError(seq)
			require.NoError(t, err)

			seq = backend.Sync(ctx, "", serverVersion, recordVersion, true)
			require.NoError(t, backend.Close())

			records, err := iterutil.CollectWithError(seq)
			assert.Len(t, records, 0)
			assert.ErrorIs(t, err, context.Canceled)
		})
	})
}

func TestSyncOldRecords(t *testing.T, backend storage.Backend) {
	t.Helper()

	sync := func(serverVersion, afterRecordVersion uint64) ([]string, error) {
		stream := backend.Sync(t.Context(), "", serverVersion, afterRecordVersion, false)

		var ids []string
		for record, err := range stream {
			if err != nil {
				return nil, err
			}
			ids = append(ids, record.GetId())
		}
		return ids, nil
	}
	syncLatest := func() (serverVersion, latestRecordVersion uint64, ids []string, err error) {
		serverVersion, latestRecordVersion, stream, err := backend.SyncLatest(t.Context(), "", nil)
		if err != nil {
			return 0, 0, nil, err
		}

		for record, err := range stream {
			if err != nil {
				return 0, 0, nil, err
			}
			ids = append(ids, record.GetId())
		}
		return serverVersion, latestRecordVersion, ids, nil
	}

	serverVersion, recordVersion, ids, err := syncLatest()
	assert.NotZero(t, serverVersion)
	assert.Empty(t, ids)
	assert.NoError(t, err)

	ids, err = sync(serverVersion, recordVersion)
	assert.Empty(t, ids)
	assert.NoError(t, err)

	rs1 := []*databroker.Record{{Type: "example", Id: "r1", Data: protoutil.NewAnyString("r1")}}
	rs2 := []*databroker.Record{{Type: "example", Id: "r2", Data: protoutil.NewAnyString("r2")}}
	rs3 := []*databroker.Record{{Type: "example", Id: "r3", Data: protoutil.NewAnyString("r3")}}

	_, err = backend.Put(t.Context(), rs1)
	require.NoError(t, err)
	time.Sleep(time.Millisecond)
	_, err = backend.Put(t.Context(), rs2)
	require.NoError(t, err)
	time.Sleep(time.Millisecond)
	tm3 := time.Now()
	_, err = backend.Put(t.Context(), rs3)
	require.NoError(t, err)
	time.Sleep(time.Millisecond)

	_, recordVersion, ids, err = syncLatest()
	assert.Equal(t, rs3[0].Version, recordVersion)
	assert.Len(t, ids, 3)
	assert.NoError(t, err)

	ids, err = sync(serverVersion, rs1[0].Version)
	assert.Len(t, ids, 2)
	assert.NoError(t, err)

	err = backend.Clean(t.Context(), storage.CleanOptions{RemoveRecordChangesBefore: tm3})
	require.NoError(t, err)

	ids, err = sync(serverVersion, rs1[0].Version)
	assert.Len(t, ids, 0)
	assert.ErrorIs(t, err, storage.ErrInvalidRecordVersion)
}

type mockRegistryWatchServer struct {
	registry.Registry_WatchServer
	context context.Context
	send    func(*registry.ServiceList) error
}

func (m mockRegistryWatchServer) Context() context.Context {
	return m.context
}

func (m mockRegistryWatchServer) Send(res *registry.ServiceList) error {
	return m.send(res)
}

func TestRegistry(t *testing.T, backend registry.RegistryServer) {
	t.Helper()

	listResults := make(chan *registry.ServiceList)
	eg, ctx := errgroup.WithContext(t.Context())
	eg.Go(func() error {
		srv := mockRegistryWatchServer{
			context: ctx,
			send: func(res *registry.ServiceList) error {
				select {
				case <-ctx.Done():
					return context.Cause(ctx)
				case listResults <- res:
				}
				return nil
			},
		}
		err := backend.Watch(&registry.ListRequest{
			Kinds: []registry.ServiceKind{
				registry.ServiceKind_AUTHENTICATE,
				registry.ServiceKind_CONSOLE,
			},
		}, srv)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return err
	})
	eg.Go(func() error {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case res := <-listResults:
			testutil.AssertProtoEqual(t, &registry.ServiceList{}, res)
		}

		res, err := backend.Report(ctx, &registry.RegisterRequest{
			Services: []*registry.Service{
				{Kind: registry.ServiceKind_AUTHENTICATE, Endpoint: "authenticate.example.com"},
				{Kind: registry.ServiceKind_AUTHORIZE, Endpoint: "authorize.example.com"},
				{Kind: registry.ServiceKind_CONSOLE, Endpoint: "console.example.com"},
			},
		})
		if err != nil {
			return fmt.Errorf("error reporting status: %w", err)
		}
		assert.NotEqual(t, 0, res.GetCallBackAfter())

		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case res := <-listResults:
			testutil.AssertProtoEqual(t, &registry.ServiceList{
				Services: []*registry.Service{
					{Kind: registry.ServiceKind_AUTHENTICATE, Endpoint: "authenticate.example.com"},
					{Kind: registry.ServiceKind_CONSOLE, Endpoint: "console.example.com"},
				},
			}, res)
		}

		return context.Canceled
	})
	err := eg.Wait()
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	assert.NoError(t, err)
}

// truncateTimestamps truncates Timestamp messages to 1 µs precision.
func truncateTimestamps(ts ...*timestamppb.Timestamp) {
	for _, t := range ts {
		t.Nanos = (t.Nanos / 1000) * 1000
	}
}
