package postgres

import (
	"fmt"
	"net/url"
	"os"
	"runtime"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestBackend(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	{
		dsn := testutil.StartPostgres(t)
		backend := New(t.Context(), dsn)
		t.Cleanup(func() { _ = backend.Close() })
		storagetest.TestBackend(t, backend)
	}

	{
		dsn := testutil.StartPostgres(t)
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
	}
}

func TestIndexing(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	dsn := testutil.StartPostgres(t)
	backend := New(t.Context(), dsn)
	t.Cleanup(func() { _ = backend.Close() })
	storagetest.TestIndexing(t, backend, storagetest.WithPostgres())
}

func TestFilter(t *testing.T) {
	t.Parallel()
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	dsn := testutil.StartPostgres(t)
	backend := New(t.Context(), dsn)
	defer backend.Close()
	storagetest.TestFilter(t, backend)
}

func TestSyncOldRecords(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	dsn := testutil.StartPostgres(t)
	backend := New(t.Context(), dsn)
	defer backend.Close()
	storagetest.TestSyncOldRecords(t, backend)
}

func TestClear(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	dsn := testutil.StartPostgres(t)
	backend := New(t.Context(), dsn)
	defer backend.Close()
	storagetest.TestClear(t, backend)
}

func BenchmarkPut(b *testing.B) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		b.Skip("Github action can not run docker on MacOS")
	}

	dsn := testutil.StartPostgres(b)
	backend := New(b.Context(), dsn)
	b.Cleanup(func() { _ = backend.Close() })
	storagetest.BenchmarkPut(b, backend)
}

func TestTransactions(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	dsn := testutil.StartPostgres(t)
	var databases atomic.Int64
	backendF := func(t *testing.T) storage.Backend {
		backend := New(t.Context(), newTestDatabase(t, dsn, databases.Add(1)))
		_, _, err := backend.init(t.Context())
		require.NoError(t, err)
		t.Cleanup(func() { _ = backend.Close() })
		return backend
	}

	storagetest.TestTransaction(t, backendF, storagetest.TransactionTestOptions{})
}

func TestTransactionsClustered(t *testing.T) {
	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	dsn := testutil.StartPostgres(t)
	var databases atomic.Int64
	clusterF := func(t *testing.T) (storage.Backend, []storage.Backend) {
		clusterDSN := newTestDatabase(t, dsn, databases.Add(1))
		newBackend := func() storage.Backend {
			backend := New(t.Context(), clusterDSN)
			t.Cleanup(func() { _ = backend.Close() })
			return backend
		}

		leader := newBackend()
		followers := make([]storage.Backend, 2)
		for i := range followers {
			followers[i] = newBackend()
		}
		return leader, followers
	}

	storagetest.TestTransactionsClustered(t, clusterF, storagetest.TransactionTestOptions{})
}

func newTestDatabase(t *testing.T, dsn string, n int64) string {
	t.Helper()

	conn, err := pgx.Connect(t.Context(), dsn)
	require.NoError(t, err)
	defer conn.Close(t.Context())

	name := fmt.Sprintf("transactions_%d", n)
	_, err = conn.Exec(t.Context(), `CREATE DATABASE `+name)
	require.NoError(t, err)

	u, err := url.Parse(dsn)
	require.NoError(t, err)
	u.Path = "/" + name
	return u.String()
}
