package postgres

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func newTransactionTestBackend(t *testing.T, dsn string) (*Backend, uint64, *pgxpool.Pool) {
	t.Helper()

	backend := New(t.Context(), dsn)
	t.Cleanup(func() { _ = backend.Close() })
	serverVersion, pool, err := backend.init(t.Context())
	require.NoError(t, err)
	return backend, serverVersion, pool
}

func acquireTransactionLock(t *testing.T, pool *pgxpool.Pool, key string) *postgresLock {
	t.Helper()

	conn, err := pool.Acquire(t.Context())
	require.NoError(t, err)
	lock := newPostgresLock(conn, key)
	acquired, err := lock.tryAcquire(t.Context())
	require.NoError(t, err)
	require.True(t, acquired)
	t.Cleanup(lock.release)
	return lock
}

// waitForLeaderTest joins a flight the way doTransaction does: on a registered
// connection that has failed to take the lock.
func waitForLeaderTest(
	ctx context.Context, t *testing.T, backend *Backend, pool *pgxpool.Pool, key string,
) ([]*databroker.Record, bool, error) {
	t.Helper()

	conn, err := pool.Acquire(ctx)
	require.NoError(t, err)
	lock := newPostgresLock(conn, key)
	require.NoError(t, backend.register(lock.pooledConn))
	defer backend.unregister(lock.pooledConn)
	defer lock.release()

	return waitForResults(ctx, lock.pooledConn, key)
}

// putRecord returns its error rather than failing the test: it runs on the
// leader's goroutine, where a require would Goexit and strand the caller.
func putRecord(tx storage.Transaction, id string) error {
	_, err := tx.Submit(&databroker.TransactionRequest{
		Operation: &databroker.TransactionRequest_Put{Put: &databroker.PutRequest{
			Records: []*databroker.Record{{Type: "test", Id: id, Data: protoutil.NewAnyString(id)}},
		}},
	})
	return err
}

func TestTransactionLeader(t *testing.T) {
	dsn := testutil.StartPostgres(t)
	var databases atomic.Int64
	dsnF := func(t *testing.T) string {
		return newTestDatabase(t, dsn, databases.Add(1))
	}

	t.Run("returns and publishes the changed records", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		lock := acquireTransactionLock(t, pool, "foo")

		changed, err := backend.doTransactionLocked(t.Context(), pool, lock.pooledConn, serverVersion, "foo",
			func(tx storage.Transaction) error {
				return putRecord(tx, "r1")
			})
		require.NoError(t, err)
		require.Len(t, changed, 1)
		assert.Equal(t, "r1", changed[0].GetId())

		flight, err := getTransaction(t.Context(), pool, "foo")
		require.NoError(t, err)
		require.NotNil(t, flight)
		assert.True(t, flight.completed)

		published, err := flight.result()
		require.NoError(t, err)
		require.Len(t, published, 1)
		assert.Equal(t, "r1", published[0].GetId())
	})

	t.Run("returns and publishes the callback error", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		lock := acquireTransactionLock(t, pool, "foo")

		changed, err := backend.doTransactionLocked(t.Context(), pool, lock.pooledConn, serverVersion, "foo",
			func(tx storage.Transaction) error {
				_ = putRecord(tx, "r1")
				return errors.New("boom")
			})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "boom")
		assert.Empty(t, changed)

		flight, err := getTransaction(t.Context(), pool, "foo")
		require.NoError(t, err)
		require.NotNil(t, flight)
		assert.True(t, flight.completed)

		_, resultErr := flight.result()
		require.Error(t, resultErr)
		assert.Contains(t, resultErr.Error(), "boom")
	})

	t.Run("a failed transaction is not committed", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		lock := acquireTransactionLock(t, pool, "foo")

		_, err := backend.doTransactionLocked(t.Context(), pool, lock.pooledConn, serverVersion, "foo",
			func(tx storage.Transaction) error {
				_ = putRecord(tx, "r1")
				return errors.New("boom")
			})
		require.Error(t, err)

		_, err = backend.Get(t.Context(), "test", "r1")
		assert.ErrorIs(t, err, storage.ErrNotFound)
	})

	t.Run("each flight replaces the previous one", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		lock := acquireTransactionLock(t, pool, "foo")

		_, err := backend.doTransactionLocked(t.Context(), pool, lock.pooledConn, serverVersion, "foo",
			func(tx storage.Transaction) error {
				return putRecord(tx, "r1")
			})
		require.NoError(t, err)
		first, err := getTransaction(t.Context(), pool, "foo")
		require.NoError(t, err)

		_, err = backend.doTransactionLocked(t.Context(), pool, lock.pooledConn, serverVersion, "foo",
			func(tx storage.Transaction) error {
				return putRecord(tx, "r2")
			})
		require.NoError(t, err)
		second, err := getTransaction(t.Context(), pool, "foo")
		require.NoError(t, err)

		assert.NotEqual(t, first.id, second.id)
		published, err := second.result()
		require.NoError(t, err)
		require.Len(t, published, 1)
		assert.Equal(t, "r2", published[0].GetId())
	})

	t.Run("flights are per key", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))

		for _, key := range []string{"foo", "bar"} {
			lock := acquireTransactionLock(t, pool, key)
			_, err := backend.doTransactionLocked(t.Context(), pool, lock.pooledConn, serverVersion, key,
				func(tx storage.Transaction) error {
					return putRecord(tx, key)
				})
			require.NoError(t, err)
		}

		for _, key := range []string{"foo", "bar"} {
			flight, err := getTransaction(t.Context(), pool, key)
			require.NoError(t, err)
			require.NotNil(t, flight)
			published, err := flight.result()
			require.NoError(t, err)
			require.Len(t, published, 1)
			assert.Equal(t, key, published[0].GetId())
		}
	})

	t.Run("a destroyed lock fails the transaction", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		lock := acquireTransactionLock(t, pool, "foo")
		lock.destroy()

		_, err := backend.doTransactionLocked(t.Context(), pool, lock.pooledConn, serverVersion, "foo",
			func(storage.Transaction) error { return nil })
		assert.ErrorIs(t, err, errBackendClosed)
	})
}

// startLeader runs a flight on key that blocks inside its callback until the
// returned finish function is called.
func startLeader(
	t *testing.T, backend *Backend, pool *pgxpool.Pool, serverVersion uint64, key string,
	fn func(tx storage.Transaction) error,
) (finish func() ([]*databroker.Record, error)) {
	t.Helper()

	started := make(chan struct{})
	release := make(chan struct{})
	type result struct {
		changed []*databroker.Record
		err     error
	}
	done := make(chan result, 1)

	lock := acquireTransactionLock(t, pool, key)
	go func() {
		changed, err := backend.doTransactionLocked(t.Context(), pool, lock.pooledConn, serverVersion, key,
			func(tx storage.Transaction) error {
				close(started)
				<-release
				return fn(tx)
			})
		done <- result{changed, err}
	}()
	<-started

	return func() ([]*databroker.Record, error) {
		close(release)
		r := <-done
		return r.changed, r.err
	}
}

// startWaiter joins the flight on key in the background, returning once the
// waiter has had time to read the in-flight row and park on its connection.
func startWaiter(
	t *testing.T, backend *Backend, pool *pgxpool.Pool, key string,
) (join func() ([]*databroker.Record, bool, error)) {
	t.Helper()

	type result struct {
		changed []*databroker.Record
		joined  bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		changed, joined, err := waitForLeaderTest(t.Context(), t, backend, pool, key)
		done <- result{changed, joined, err}
	}()
	time.Sleep(500 * time.Millisecond)

	return func() ([]*databroker.Record, bool, error) {
		r := <-done
		return r.changed, r.joined, r.err
	}
}

func TestTransactionWaiter(t *testing.T) {
	dsn := testutil.StartPostgres(t)
	var databases atomic.Int64
	dsnF := func(t *testing.T) string {
		return newTestDatabase(t, dsn, databases.Add(1))
	}

	t.Run("nothing in flight", func(t *testing.T) {
		backend, _, pool := newTransactionTestBackend(t, dsnF(t))

		changed, joined, err := waitForLeaderTest(t.Context(), t, backend, pool, "foo")
		require.NoError(t, err)
		assert.False(t, joined)
		assert.Empty(t, changed)
	})

	t.Run("an already completed flight is not joined", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		lock := acquireTransactionLock(t, pool, "foo")
		_, err := backend.doTransactionLocked(t.Context(), pool, lock.pooledConn, serverVersion, "foo",
			func(tx storage.Transaction) error {
				return putRecord(tx, "r1")
			})
		require.NoError(t, err)

		changed, joined, err := waitForLeaderTest(t.Context(), t, backend, pool, "foo")
		require.NoError(t, err)
		assert.False(t, joined)
		assert.Empty(t, changed)
	})

	t.Run("joins the results of the in-flight leader", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		finish := startLeader(t, backend, pool, serverVersion, "foo", func(tx storage.Transaction) error {
			return putRecord(tx, "r1")
		})
		join := startWaiter(t, backend, pool, "foo")

		_, err := finish()
		require.NoError(t, err)

		changed, joined, waitErr := join()
		require.NoError(t, waitErr)
		assert.True(t, joined)
		require.Len(t, changed, 1)
		assert.Equal(t, "r1", changed[0].GetId())
	})

	t.Run("joins the error of the in-flight leader", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		finish := startLeader(t, backend, pool, serverVersion, "foo", func(storage.Transaction) error {
			return errors.New("boom")
		})
		join := startWaiter(t, backend, pool, "foo")

		_, err := finish()
		require.Error(t, err)

		_, joined, waitErr := join()
		assert.True(t, joined)
		require.Error(t, waitErr)
		assert.Contains(t, waitErr.Error(), "boom")
	})

	t.Run("does not join a flight on another key", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		finish := startLeader(t, backend, pool, serverVersion, "foo", func(tx storage.Transaction) error {
			return putRecord(tx, "r1")
		})
		t.Cleanup(func() { _, _ = finish() })

		changed, joined, err := waitForLeaderTest(t.Context(), t, backend, pool, "bar")
		require.NoError(t, err)
		assert.False(t, joined)
		assert.Empty(t, changed)
	})

	t.Run("gives up when the flight does not complete in time", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		finish := startLeader(t, backend, pool, serverVersion, "foo", func(tx storage.Transaction) error {
			return putRecord(tx, "r1")
		})
		t.Cleanup(func() { _, _ = finish() })

		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		changed, joined, err := waitForLeaderTest(ctx, t, backend, pool, "foo")
		require.NoError(t, err)
		assert.False(t, joined)
		assert.Empty(t, changed)
	})

	t.Run("closing the backend unblocks a waiter", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		finish := startLeader(t, backend, pool, serverVersion, "foo", func(tx storage.Transaction) error {
			return putRecord(tx, "r1")
		})
		t.Cleanup(func() { _, _ = finish() })

		join := startWaiter(t, backend, pool, "foo")

		waited := make(chan struct{})
		go func() {
			defer close(waited)
			_, _, _ = join()
		}()

		_ = backend.Close()
		requireReceive(t, waited, 10*time.Second, "waiter did not return after the backend was closed")
	})

	t.Run("waiting does not leak listening connections", func(t *testing.T) {
		backend, serverVersion, pool := newTransactionTestBackend(t, dsnF(t))
		finish := startLeader(t, backend, pool, serverVersion, "foo", func(tx storage.Transaction) error {
			return putRecord(tx, "r1")
		})
		t.Cleanup(func() { _, _ = finish() })

		for range 8 {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			_, joined, err := waitForLeaderTest(ctx, t, backend, pool, "foo")
			cancel()
			require.NoError(t, err)
			assert.False(t, joined)
		}
		// background tasks
		assert.LessOrEqual(t, pool.Stat().AcquiredConns(), int32(2))
	})
}

func TestLockPrimitives(t *testing.T) {
	dsn := testutil.StartPostgres(t)
	var databases atomic.Int64
	dsnF := func(t *testing.T) string {
		return newTestDatabase(t, dsn, databases.Add(1))
	}

	t.Run("locks cannot use a closed connection", func(t *testing.T) {
		pool, lock := newLockedPool(t, dsnF(t), "foo")

		lock.destroy()
		pool.Close()

		lockErr := lock.do(func(q querier) error {
			_, err := q.Exec(t.Context(), "")
			return err
		})
		require.Error(t, lockErr)
		assert.ErrorIs(t, lockErr, errBackendClosed)
	})

	t.Run("sequential", func(t *testing.T) {
		pool, lock := newLockedPool(t, dsnF(t), "foo")
		lock.release()

		lock2 := acquireTransactionLock(t, pool, "foo")
		lock2.release()
		pool.Close()
	})

	t.Run("release twice ok", func(t *testing.T) {
		pool, lock := newLockedPool(t, dsnF(t), "foo")

		lock.release()
		lock.release()
		pool.Close()
	})

	t.Run("releasing a lock allows the pool to close", func(t *testing.T) {
		pool, lock := newLockedPool(t, dsnF(t), "foo")

		closed := startClosingPool(pool)
		requireNotReceive(t, closed, 250*time.Millisecond, "the pool to close while the lock held a connection")

		lock.release()
		requireReceive(t, closed, 10*time.Second, "the pool to close")
	})

	t.Run("killing a lock allows the pool to close", func(t *testing.T) {
		pool, lock := newLockedPool(t, dsnF(t), "bar")

		closed := startClosingPool(pool)
		requireNotReceive(t, closed, 250*time.Millisecond, "the pool to close while the lock held a connection")

		lock.kill(errBackendClosed)
		requireReceive(t, closed, 10*time.Second, "the pool to close")
	})
}

func newLockedPool(t *testing.T, dsn, key string) (*pgxpool.Pool, *postgresLock) {
	t.Helper()

	config, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	pool, err := pgxpool.NewWithConfig(t.Context(), config)
	require.NoError(t, err)
	conn, err := pool.Acquire(t.Context())
	require.NoError(t, err)

	lock := newPostgresLock(conn, key)
	acquired, err := lock.tryAcquire(t.Context())
	require.NoError(t, err)
	require.True(t, acquired)
	return pool, lock
}

func startClosingPool(pool *pgxpool.Pool) (closed chan struct{}) {
	closed = make(chan struct{})
	go func() {
		defer close(closed)
		pool.Close()
	}()
	return closed
}

func requireReceive[T any](t *testing.T, c <-chan T, timeout time.Duration, what string) (v T) {
	t.Helper()

	select {
	case v = <-c:
	case <-time.After(timeout):
		assert.Fail(t, "timed out waiting for "+what)
	}
	return v
}

func requireNotReceive[T any](t *testing.T, c <-chan T, within time.Duration, what string) {
	t.Helper()

	select {
	case <-c:
		assert.Fail(t, "unexpected "+what)
	case <-time.After(within):
	}
}
