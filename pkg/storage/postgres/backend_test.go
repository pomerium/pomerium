package postgres

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestBackend(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	testutil.WithTestPostgres(t, func(dsn string) {
		backend := New(t.Context(), dsn)
		t.Cleanup(func() { _ = backend.Close() })

		storagetest.TestBackend(t, backend)
	})

	testutil.WithTestPostgres(t, func(dsn string) {
		backend := New(t.Context(), dsn)
		t.Cleanup(func() { _ = backend.Close() })

		t.Run("unknown type", func(t *testing.T) {
			_, pool, err := backend.init(t.Context())
			require.NoError(t, err)
			_, err = pool.Exec(t.Context(), `
				INSERT INTO `+schemaName+"."+recordsTableName+` (type, id, version, data)
				VALUES ('unknown', '1', 1000, '{"@type":"UNKNOWN","value":{}}')
			`)
			assert.NoError(t, err)

			_, err = backend.Get(t.Context(), "unknown", "1")
			assert.ErrorIs(t, err, storage.ErrNotFound)

			_, _, seq, err := backend.SyncLatest(t.Context(), "unknown", nil)
			if assert.NoError(t, err) {
				records, err := iterutil.CollectWithError(seq)
				assert.NoError(t, err)
				assert.Len(t, records, 1)
			}
		})
	})

	t.Run("other fields", func(t *testing.T) {
		testutil.WithTestPostgres(t, func(dsn string) {
			backend := New(t.Context(), dsn)
			t.Cleanup(func() { _ = backend.Close() })

			_, err := backend.Put(t.Context(), []*databroker.Record{
				databroker.NewRecord(&session.Session{Id: "s1", UserId: "u1"}),
				databroker.NewRecord(&session.Session{Id: "s2", UserId: "u2"}),
				databroker.NewRecord(&session.Session{Id: "s3", UserId: "u2"}),
				databroker.NewRecord(&session.Session{Id: "s4", UserId: "u3"}),
				databroker.NewRecord(&session.Session{Id: "s5", UserId: "u3"}),
				databroker.NewRecord(&session.Session{Id: "s6", UserId: "u3"}),
			})
			require.NoError(t, err)

			syncLatest := func(recordType string, filter storage.FilterExpression) [][2]string {
				_, _, seq, err := backend.SyncLatest(t.Context(), recordType, filter)
				require.NoError(t, err)
				records, err := iterutil.CollectWithError(seq)
				require.NoError(t, err)
				refs := make([][2]string, len(records))
				for i, record := range records {
					refs[i] = [2]string{record.Type, record.Id}
				}
				return refs
			}

			assert.Equal(t, [][2]string{
				{"type.googleapis.com/session.Session", "s2"},
				{"type.googleapis.com/session.Session", "s3"},
			}, syncLatest("type.googleapis.com/session.Session", storage.EqualsFilterExpression{
				Fields: []string{"user_id"},
				Value:  "u2",
			}))
		})
	})
}

func TestSyncOldRecords(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	testutil.WithTestPostgres(t, func(dsn string) {
		backend := New(t.Context(), dsn)
		defer backend.Close()

		storagetest.TestSyncOldRecords(t, backend)
	})
}

func TestClear(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	testutil.WithTestPostgres(t, func(dsn string) {
		backend := New(t.Context(), dsn)
		defer backend.Close()

		storagetest.TestClear(t, backend)
	})
}

func BenchmarkPut(b *testing.B) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		b.Skip("Github action can not run docker on MacOS")
	}

	testutil.WithTestPostgres(b, func(dsn string) {
		backend := New(b.Context(), dsn)
		b.Cleanup(func() { _ = backend.Close() })

		storagetest.BenchmarkPut(b, backend)
	})
}
