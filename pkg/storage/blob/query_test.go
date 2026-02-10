package blob_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/blob"
)

func TestBlobStoreQuery(t *testing.T) {
	t.Parallel()

	tcOpts := []struct {
		name           string
		installationID string
		opts           []blob.Option
	}{
		{
			name: "without installation ID",
		},
		{
			name:           "with installation ID",
			installationID: "inst-1",
			opts:           []blob.Option{blob.WithIncludeInstallationID()},
		},
	}

	for _, tc := range tcOpts {
		t.Run(tc.name, BlobQueryConformanceTest(tc.installationID, tc.opts...))
	}
}

func BlobQueryConformanceTest(installationID string, opts ...blob.Option) func(t *testing.T) {
	return func(t *testing.T) {
		t.Parallel()
		bucket := objstore.NewInMemBucket()
		cfg := &config.Config{Options: &config.Options{InstallationID: installationID}}
		store, err := blob.NewStore[*session.Session](context.Background(), "test-prefix", bucket, cfg, opts...)
		require.NoError(t, err)
		t.Cleanup(store.Stop)

		ctx := context.Background()
		sessions := []*session.Session{
			{Id: "s1", UserId: "user-a", IdToken: &session.IDToken{Issuer: "https://idp.example.com", Subject: "sub-1"}},
			{Id: "s2", UserId: "user-b", IdToken: &session.IDToken{Issuer: "https://idp.other.com", Subject: "sub-2"}},
			{Id: "s3", UserId: "user-a", IdToken: &session.IDToken{Issuer: "https://idp.example.com", Subject: "sub-3"}},
		}
		for _, s := range sessions {
			require.NoError(t, store.Put(ctx, s.Id, bytes.NewReader(mustMarshalSession(t, s)), bytes.NewReader([]byte("body"))))
		}

		t.Run("nil filter returns all", testQueryNilFilter(store))
		t.Run("equals filter", testQueryEqualsFilter(store))
		t.Run("equals filter no match", testQueryEqualsFilterNoMatch(store))
		t.Run("and filter", testQueryAndFilter(store))
		t.Run("or filter", testQueryOrFilter(store))
		t.Run("not filter", testQueryNotFilter(store))
		t.Run("nested field filter", testQueryNestedFieldFilter(store))
		t.Run("composite filter", testQueryCompositeFilter(store))
	}
}

func testQueryNilFilter(store *blob.Store[*session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		results, err := store.QueryMetadata(context.Background())
		require.NoError(t, err)
		assert.Len(t, results, 3)
	}
}

func testQueryEqualsFilter(store *blob.Store[*session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		results, err := store.QueryMetadata(context.Background(), blob.WithQueryFilter(storage.MustEqualsFilterExpression("user_id", "user-a")))
		require.NoError(t, err)
		assert.Len(t, results, 2)
		for _, r := range results {
			assert.Equal(t, "user-a", r.GetUserId())
		}
	}
}

func testQueryEqualsFilterNoMatch(store *blob.Store[*session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		results, err := store.QueryMetadata(context.Background(), blob.WithQueryFilter(storage.MustEqualsFilterExpression("user_id", "user-z")))
		require.NoError(t, err)
		assert.Empty(t, results)
	}
}

func testQueryAndFilter(store *blob.Store[*session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		results, err := store.QueryMetadata(context.Background(), blob.WithQueryFilter(storage.AndFilterExpression{
			storage.MustEqualsFilterExpression("user_id", "user-a"),
			storage.MustEqualsFilterExpression("id", "s3"),
		}))
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "s3", results[0].GetId())
	}
}

func testQueryOrFilter(store *blob.Store[*session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		results, err := store.QueryMetadata(context.Background(), blob.WithQueryFilter(storage.OrFilterExpression{
			storage.MustEqualsFilterExpression("id", "s1"),
			storage.MustEqualsFilterExpression("id", "s2"),
		}))
		require.NoError(t, err)
		assert.Len(t, results, 2)
	}
}

func testQueryNotFilter(store *blob.Store[*session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		results, err := store.QueryMetadata(context.Background(), blob.WithQueryFilter(storage.NotFilterExpression{
			FilterExpression: storage.MustEqualsFilterExpression("user_id", "user-b"),
		}))
		require.NoError(t, err)
		assert.Len(t, results, 2)
		for _, r := range results {
			assert.NotEqual(t, "user-b", r.GetUserId())
		}
	}
}

func testQueryNestedFieldFilter(store *blob.Store[*session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := context.Background()

		// filter on nested field id_token.issuer
		results, err := store.QueryMetadata(ctx, blob.WithQueryFilter(storage.MustEqualsFilterExpression("id_token.issuer", "https://idp.example.com")))
		require.NoError(t, err)
		assert.Len(t, results, 2)
		for _, r := range results {
			assert.Equal(t, "https://idp.example.com", r.GetIdToken().GetIssuer())
		}

		// combine top-level and nested field
		results, err = store.QueryMetadata(ctx, blob.WithQueryFilter(storage.AndFilterExpression{
			storage.MustEqualsFilterExpression("id_token.issuer", "https://idp.example.com"),
			storage.MustEqualsFilterExpression("id_token.subject", "sub-3"),
		}))
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "s3", results[0].GetId())
	}
}

func testQueryCompositeFilter(store *blob.Store[*session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		ctx := context.Background()

		// top-level AND nested field
		results, err := store.QueryMetadata(ctx, blob.WithQueryFilter(storage.AndFilterExpression{
			storage.MustEqualsFilterExpression("user_id", "user-a"),
			storage.MustEqualsFilterExpression("id_token.issuer", "https://idp.example.com"),
		}))
		require.NoError(t, err)
		assert.Len(t, results, 2)

		// OR inside AND: user-a with either issuer
		results, err = store.QueryMetadata(ctx, blob.WithQueryFilter(storage.AndFilterExpression{
			storage.MustEqualsFilterExpression("user_id", "user-a"),
			storage.OrFilterExpression{
				storage.MustEqualsFilterExpression("id_token.subject", "sub-1"),
				storage.MustEqualsFilterExpression("id_token.subject", "sub-3"),
			},
		}))
		require.NoError(t, err)
		assert.Len(t, results, 2)

		// NOT combined with AND
		results, err = store.QueryMetadata(ctx, blob.WithQueryFilter(storage.AndFilterExpression{
			storage.MustEqualsFilterExpression("user_id", "user-a"),
			storage.NotFilterExpression{
				FilterExpression: storage.MustEqualsFilterExpression("id_token.subject", "sub-1"),
			},
		}))
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "s3", results[0].GetId())

		// OR of ANDs
		results, err = store.QueryMetadata(ctx, blob.WithQueryFilter(storage.OrFilterExpression{
			storage.AndFilterExpression{
				storage.MustEqualsFilterExpression("user_id", "user-a"),
				storage.MustEqualsFilterExpression("id_token.subject", "sub-1"),
			},
			storage.AndFilterExpression{
				storage.MustEqualsFilterExpression("user_id", "user-b"),
				storage.MustEqualsFilterExpression("id_token.subject", "sub-2"),
			},
		}))
		require.NoError(t, err)
		assert.Len(t, results, 2)
	}
}

func TestBlobStoreQuery_AcrossInstallationIDs(t *testing.T) {
	t.Parallel()
	bucket := objstore.NewInMemBucket()
	cfg := &config.Config{Options: &config.Options{InstallationID: "inst-1"}}
	store, err := blob.NewStore[*session.Session](context.Background(), "test-prefix", bucket, cfg, blob.WithIncludeInstallationID())
	require.NoError(t, err)
	t.Cleanup(store.Stop)
	ctx := context.Background()

	s1 := &session.Session{Id: "s1", UserId: "user-a"}
	require.NoError(t, store.Put(ctx, "s1", bytes.NewReader(mustMarshalSession(t, s1)), bytes.NewReader([]byte("body"))))

	store.OnConfigChange(ctx, &config.Config{Options: &config.Options{InstallationID: "inst-2"}})
	s2 := &session.Session{Id: "s2", UserId: "user-b"}
	require.NoError(t, store.Put(ctx, "s2", bytes.NewReader(mustMarshalSession(t, s2)), bytes.NewReader([]byte("body"))))

	t.Run("query scoped to installation ID", func(t *testing.T) {
		results, err := store.QueryMetadata(ctx, blob.WithQueryInstallationID("inst-1"))
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "s1", results[0].GetId())
	})

	t.Run("query across all installations", func(t *testing.T) {
		results, err := store.QueryMetadata(ctx)
		require.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("filter across all installations", func(t *testing.T) {
		results, err := store.QueryMetadata(ctx, blob.WithQueryFilter(storage.MustEqualsFilterExpression("user_id", "user-a")))
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "s1", results[0].GetId())
	})
}
