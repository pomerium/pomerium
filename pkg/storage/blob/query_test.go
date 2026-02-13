package blob_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"

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
			opts: []blob.Option{blob.WithInMemory()},
		},
		{
			name:           "with installation ID",
			installationID: "inst-1",
			opts:           []blob.Option{blob.WithIncludeInstallationID(), blob.WithInMemory()},
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
		store := blob.NewStore[session.Session](context.Background(), "test-prefix", opts...)
		store.OnConfigChange(t.Context(), bucket)
		t.Cleanup(store.Stop)

		sessions := []*session.Session{
			{Id: "s1", UserId: "user-a", IdToken: &session.IDToken{Issuer: "https://idp.example.com", Subject: "sub-1"}},
			{Id: "s2", UserId: "user-b", IdToken: &session.IDToken{Issuer: "https://idp.other.com", Subject: "sub-2"}},
			{Id: "s3", UserId: "user-a", IdToken: &session.IDToken{Issuer: "https://idp.example.com", Subject: "sub-3"}},
		}
		for _, s := range sessions {
			putWithContent(t, store, s.Id, mustMarshalSession(t, s), []byte("body"))
		}

		t.Run("nil filter returns all", testQueryNilFilter(store))
		t.Run("equals filter", testQueryEqualsFilter(store))
		t.Run("equals filter no match", testQueryEqualsFilterNoMatch(store))
		t.Run("and filter", testQueryAndFilter(store))
		t.Run("or filter", testQueryOrFilter(store))
		t.Run("not filter", testQueryNotFilter(store))
		t.Run("nested field filter", testQueryNestedFieldFilter(store))
		t.Run("composite filter", testQueryCompositeFilter(store))
		t.Run("order by ascending", testQueryOrderByAscending(store))
		t.Run("order by descending", testQueryOrderByDescending(store))
		t.Run("order by multiple fields", testQueryOrderByMultipleFields(store))
		t.Run("order by nested field", testQueryOrderByNestedField(store))
		t.Run("order by with filter", testQueryOrderByWithFilter(store))
	}
}

func testQueryNilFilter(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		results, err := store.QueryMetadata(context.Background())
		require.NoError(t, err)
		assert.Len(t, results, 3)
	}
}

func testQueryEqualsFilter(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
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

func testQueryEqualsFilterNoMatch(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		results, err := store.QueryMetadata(context.Background(), blob.WithQueryFilter(storage.MustEqualsFilterExpression("user_id", "user-z")))
		require.NoError(t, err)
		assert.Empty(t, results)
	}
}

func testQueryAndFilter(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
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

func testQueryOrFilter(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
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

func testQueryNotFilter(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
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

func testQueryNestedFieldFilter(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
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

func testQueryCompositeFilter(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
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
	// FIXME: because it creates a new bucket in memory on OnConfigChange
	t.Skip()
	bucket := objstore.NewInMemBucket()
	store := blob.NewStore[session.Session](context.Background(), "test-prefix", blob.WithIncludeInstallationID(), blob.WithInMemory())
	store.OnConfigChange(t.Context(), bucket)
	t.Cleanup(store.Stop)

	s1 := &session.Session{Id: "s1", UserId: "user-a"}
	putWithContent(t, store, "s1", mustMarshalSession(t, s1), []byte("body"))

	bucket2 := objstore.NewInMemBucket()
	store.OnConfigChange(t.Context(), bucket2)
	s2 := &session.Session{Id: "s2", UserId: "user-b"}
	putWithContent(t, store, "s2", mustMarshalSession(t, s2), []byte("body"))

	t.Run("query scoped to installation ID", func(t *testing.T) {
		results, err := store.QueryMetadata(t.Context(), blob.WithQueryInstallationID("inst-1"))
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "s1", results[0].GetId())
	})

	t.Run("query across all installations", func(t *testing.T) {
		results, err := store.QueryMetadata(t.Context())
		require.NoError(t, err)
		assert.Len(t, results, 2)
	})

	t.Run("filter across all installations", func(t *testing.T) {
		results, err := store.QueryMetadata(t.Context(), blob.WithQueryFilter(storage.MustEqualsFilterExpression("user_id", "user-a")))
		require.NoError(t, err)
		require.Len(t, results, 1)
		assert.Equal(t, "s1", results[0].GetId())
	})
}

func testQueryOrderByAscending(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		results, err := store.QueryMetadata(context.Background(),
			blob.WithQueryOrderBy(storage.OrderByFromString("id")),
		)
		require.NoError(t, err)
		require.Len(t, results, 3)
		assert.Equal(t, "s1", results[0].GetId())
		assert.Equal(t, "s2", results[1].GetId())
		assert.Equal(t, "s3", results[2].GetId())
	}
}

func testQueryOrderByDescending(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		results, err := store.QueryMetadata(context.Background(),
			blob.WithQueryOrderBy(storage.OrderByFromString("-id")),
		)
		require.NoError(t, err)
		require.Len(t, results, 3)
		assert.Equal(t, "s3", results[0].GetId())
		assert.Equal(t, "s2", results[1].GetId())
		assert.Equal(t, "s1", results[2].GetId())
	}
}

func testQueryOrderByMultipleFields(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		// Primary sort by user_id ascending, secondary by id descending.
		// user-a has s1 and s3; user-b has s2.
		// Expected: user-a first (s3 before s1 due to -id), then user-b (s2).
		results, err := store.QueryMetadata(context.Background(),
			blob.WithQueryOrderBy(storage.OrderByFromString("user_id,-id")),
		)
		require.NoError(t, err)
		require.Len(t, results, 3)
		assert.Equal(t, "s3", results[0].GetId())
		assert.Equal(t, "s1", results[1].GetId())
		assert.Equal(t, "s2", results[2].GetId())
	}
}

func testQueryOrderByNestedField(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		// Sort by id_token.subject ascending: sub-1 (s1), sub-2 (s2), sub-3 (s3).
		results, err := store.QueryMetadata(context.Background(),
			blob.WithQueryOrderBy(storage.OrderByFromString("id_token.subject")),
		)
		require.NoError(t, err)
		require.Len(t, results, 3)
		assert.Equal(t, "s1", results[0].GetId())
		assert.Equal(t, "s2", results[1].GetId())
		assert.Equal(t, "s3", results[2].GetId())
	}
}

func testQueryOrderByWithFilter(store *blob.Store[session.Session, *session.Session]) func(t *testing.T) {
	return func(t *testing.T) {
		t.Helper()
		// Filter to user-a sessions, then sort by id descending.
		results, err := store.QueryMetadata(context.Background(),
			blob.WithQueryFilter(storage.MustEqualsFilterExpression("user_id", "user-a")),
			blob.WithQueryOrderBy(storage.OrderByFromString("-id")),
		)
		require.NoError(t, err)
		require.Len(t, results, 2)
		assert.Equal(t, "s3", results[0].GetId())
		assert.Equal(t, "s1", results[1].GetId())
	}
}
