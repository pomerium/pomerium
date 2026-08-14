package postgres

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// postgresLock acquires advisory locks on the connection it owns.
// it creates *pooledConn to keep transactions cancellable when backend.Close
// is called.
type postgresLock struct {
	*pooledConn
	key string

	acquired atomic.Bool
}

func newPostgresLock(conn *pgxpool.Conn, key string) *postgresLock {
	return &postgresLock{pooledConn: newPooledConn(conn), key: key}
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
