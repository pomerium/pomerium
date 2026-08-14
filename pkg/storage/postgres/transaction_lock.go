package postgres

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// postgresLock acquires advisory locks on the connection it owns.
// it creates *pooledConn to keep transactions cancellable when backend.Close
// is called.
type postgresLock struct {
	*pooledConn
	key string

	acquired atomic.Bool
}

func newPostgresLock(conn *pooledConn, key string) *postgresLock {
	return &postgresLock{pooledConn: conn, key: key}
}

func (l *postgresLock) tryAcquire(ctx context.Context) (acquired bool, err error) {
	err = l.do(func(q querier) error {
		err := q.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, $2))`,
			l.key, int64(transactionLockSeed)).Scan(&acquired)
		if acquired {
			l.acquired.Store(true)
		}
		return err
	})
	if err != nil {
		return false, fmt.Errorf("postgres: failed to acquire transaction lock: %w", err)
	}
	return acquired, nil
}

// release must never hand a connection still holding the session lock back to
// the pool, so on any failure the connection is closed instead.
func (l *postgresLock) release() {
	l.closeWith(func(ctx context.Context, q querier) bool {
		return !l.acquired.Load() || l.unlock(ctx, q)
	})
}

func (l *postgresLock) unlock(ctx context.Context, q querier) (unlocked bool) {
	err := q.QueryRow(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, $2))`,
		l.key, int64(transactionLockSeed)).Scan(&unlocked)
	return err == nil && unlocked
}

const connCloseTimeout = 5 * time.Second

// pooledConn owns a connection borrowed from the pool for longer than a single
// query.
// Typically, pool.Close expects there to be no active connections and waits for them to close.
// Instead, since transactions can be opened for long periods of time,
// we actively close connections when backend.Close is called.
type pooledConn struct {
	// kill cancels through this rather than conn, which it may not read: the
	// goroutine being killed can be releasing conn at the same time
	abort *pgconn.PgConn

	mu     sync.Mutex
	conn   *pgxpool.Conn
	onKill context.CancelFunc
}

func newPooledConn(conn *pgxpool.Conn) *pooledConn {
	return &pooledConn{abort: conn.Conn().PgConn(), conn: conn}
}

func (c *pooledConn) do(fn func(q querier) error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return errBackendClosed
	}
	return fn(c.conn)
}

func (c *pooledConn) begin(ctx context.Context) (pgx.Tx, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil, errBackendClosed
	}
	return c.conn.Begin(ctx)
}

// park hands out the raw connection for a blocking read, which cannot hold the
// connection lock. cancel is what kill uses to end that read.
func (c *pooledConn) park(cancel context.CancelFunc) (*pgx.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil, errBackendClosed
	}
	c.onKill = cancel
	return c.conn.Conn(), nil
}

func (c *pooledConn) unpark() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.onKill = nil
}

func (c *pooledConn) kill(error) {
	c.mu.Lock()
	dead, onKill := c.conn == nil, c.onKill
	c.mu.Unlock()
	if dead {
		return
	}
	// neither alone is enough: CancelRequest ends a running query, onKill ends a
	// blocking read with no query behind it. Both run outside the connection lock,
	// which whatever they are aborting is holding.
	if onKill != nil {
		onKill()
	}
	_ = c.abort.CancelRequest(context.Background())

	c.destroy()
}

// destroy closes the connection and hands it back to the pool so Close can
// drain while the caller is still using it.
func (c *pooledConn) destroy() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return
	}
	_ = c.conn.Conn().Close(context.TODO())
	c.conn.Release()
	c.conn = nil
}

func (c *pooledConn) returnToPool() {
	c.closeWith(func(context.Context, querier) bool { return true })
}

// closeWith releases the connection to the pool. it accepts a callback that is expected to
// undo anything the connection still holds (advisory locks, LISTEN registrations) and reports
// whether that succeeded; if it did not, the connection is closed instead.
func (c *pooledConn) closeWith(cleanUp func(ctx context.Context, q querier) bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), connCloseTimeout)
	defer cancel()
	if !cleanUp(ctx, c.conn) {
		_ = c.conn.Conn().Close(ctx)
	}
	c.conn.Release()
	c.conn = nil
}

func (backend *Backend) wrapTransactionWithLock(
	ctx context.Context, key string, fn func(tx storage.Transaction) error,
) ([]*databroker.Record, bool, error) {
	release, serverVersion, conn, err := backend.newTransactionConn(ctx)
	defer release()
	if err != nil {
		return nil, false, err
	}
	lock := newPostgresLock(newPooledConn(conn), key)
	// registered before the first query so Close can reclaim the connection at
	// any point, not just while the callback is running
	if err := backend.register(lock.pooledConn); err != nil {
		lock.release()
		return nil, false, err
	}
	defer backend.unregister(lock.pooledConn)

	holdsLock, err := lock.tryAcquire(ctx)
	if err != nil {
		return nil, false, err
	}
	defer lock.release()

	if holdsLock {
		changed, err := backend.doTransactionLocked(ctx, lock.pooledConn, serverVersion, key, fn)
		return changed, false, err
	}
	return waitForResults(ctx, lock.pooledConn, key)
}

// waitForResults shares the result of the transaction in flight on the key. joined
// is false when there is nothing to share: no flight was in progress, or none
// completed before the deadline.
func waitForResults(
	ctx context.Context, conn *pooledConn, key string,
) ([]*databroker.Record, bool, error) {
	caller := ctx
	// the leader publishes its flight right after taking the lock, so only that
	// short window is worth polling for; the full duration is for the flight itself
	graceCtx, cancelGrace := context.WithTimeout(ctx, transactionJoinGrace)
	defer cancelGrace()

	w, err := newTransactionWaiter(ctx, conn)
	if err != nil {
		return nil, false, err
	}
	defer w.close()

	for {
		// LISTEN precedes this read, so any flight still running here will wake the
		// wait below
		before, err := w.getTransaction(ctx, key)
		if err != nil {
			return nil, false, err
		}
		if before != nil {
			if before.completed {
				return nil, false, nil
			}
			return w.joinFlight(ctx, key, before)
		}

		// the leader holds the lock but has not published a flight yet, or died
		// without finishing one
		select {
		case <-graceCtx.Done():
			// our own deadline means there was nothing to join, not a failure
			if caller.Err() != nil {
				return nil, false, context.Cause(caller)
			}
			return nil, false, nil
		case <-time.After(transactionJoinBackoff):
		}
	}
}

// transactionWaiter listens on its connection for flight completions. The LISTEN
// must never leak back into the pool, so on any failure the connection is closed
// instead.
type transactionWaiter struct {
	conn   *pooledConn
	broken atomic.Bool
}

func newTransactionWaiter(ctx context.Context, conn *pooledConn) (*transactionWaiter, error) {
	w := &transactionWaiter{conn: conn}
	err := conn.do(func(q querier) error {
		_, err := q.Exec(ctx, `LISTEN `+transactionFlightNotifyName)
		return err
	})
	if err != nil {
		w.broken.Store(true)
		return nil, fmt.Errorf("postgres: failed to listen for transaction flights: %w", err)
	}
	return w, nil
}

func (w *transactionWaiter) joinFlight(
	ctx context.Context, key string, before *inFlightTransaction,
) ([]*databroker.Record, bool, error) {
	woke, err := w.wait(ctx, before.id)
	if err != nil || !woke {
		return nil, false, err
	}

	after, err := w.getTransaction(ctx, key)
	if err != nil || after == nil || after.id != before.id || !after.completed {
		return nil, false, err
	}
	changed, err := after.result()
	return changed, true, err
}

func (w *transactionWaiter) getTransaction(ctx context.Context, key string) (*inFlightTransaction, error) {
	var f *inFlightTransaction
	err := w.conn.do(func(q querier) error {
		var err error
		f, err = getTransaction(ctx, q, key)
		return err
	})
	return f, err
}

// wait parks on the connection until the flight completes, so it runs outside the
// connection lock and relies on kill to unblock it.
func (w *transactionWaiter) wait(ctx context.Context, flightID string) (bool, error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	conn, err := w.conn.park(cancel)
	if err != nil {
		return false, err
	}
	defer w.conn.unpark()

	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			w.broken.Store(true)
			if errors.Is(err, context.DeadlineExceeded) {
				return false, nil
			}
			return false, fmt.Errorf("postgres: failed to wait for transaction flight: %w", err)
		}
		if n.Payload == flightID {
			return true, nil
		}
	}
}

func (w *transactionWaiter) close() {
	w.conn.closeWith(func(ctx context.Context, q querier) bool {
		if w.broken.Load() {
			return false
		}
		_, err := q.Exec(ctx, `UNLISTEN `+transactionFlightNotifyName)
		return err == nil
	})
}
