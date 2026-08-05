package databrokerutil_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func newSingleflightServer(t testing.TB, dialOpts ...grpc.DialOption) (databroker.Server, databrokerpb.DataBrokerServiceClient) {
	t.Helper()

	return newSingleflightServerFor(t, memoryStorage(t), dialOpts...)
}

func memoryStorage(testing.TB) config.DataBrokerOptions {
	return config.DataBrokerOptions{StorageType: config.StorageInMemoryName}
}

func fileStorage(t testing.TB) config.DataBrokerOptions {
	dir, err := os.MkdirTemp("", "pomerium-singleflight-")
	require.NoError(t, err)
	t.Cleanup(func() {
		assert.NoError(t, os.RemoveAll(dir))
	})

	return config.DataBrokerOptions{
		StorageType:             config.StorageFileName,
		StorageConnectionString: "file://" + dir,
	}
}

// postgresStorage hands every server its own database on one shared container,
// which startPostgres starts on first use and ties to the parent benchmark.
func postgresStorage(startPostgres func() string) func(testing.TB) config.DataBrokerOptions {
	var databases atomic.Int64
	return func(t testing.TB) config.DataBrokerOptions {
		return config.DataBrokerOptions{
			StorageType:             config.StoragePostgresName,
			StorageConnectionString: newBenchDatabase(t, startPostgres(), databases.Add(1)),
		}
	}
}

func newBenchDatabase(t testing.TB, dsn string, n int64) string {
	t.Helper()

	conn, err := pgx.Connect(t.Context(), dsn)
	require.NoError(t, err)
	defer conn.Close(t.Context())

	name := fmt.Sprintf("singleflight_%d", n)
	_, err = conn.Exec(t.Context(), `CREATE DATABASE `+name)
	require.NoError(t, err)

	u, err := url.Parse(dsn)
	require.NoError(t, err)
	u.Path = "/" + name
	return u.String()
}

func newSingleflightServerFor(
	t testing.TB,
	storage config.DataBrokerOptions,
	dialOpts ...grpc.DialOption,
) (databroker.Server, databrokerpb.DataBrokerServiceClient) {
	t.Helper()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), config.New(&config.Options{
		DataBroker: storage,
		SharedKey:  cryptutil.NewBase64Key(),
	}))

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	}, dialOpts...)
	return srv, databrokerpb.NewDataBrokerServiceClient(cc)
}

func singleflightRecordType() string {
	return protoutil.NewAny(new(sessionpb.Session)).TypeUrl
}

func singleflightRecord(id string) *databrokerpb.Record {
	data := protoutil.NewAny(&sessionpb.Session{Id: id})
	return &databrokerpb.Record{Type: data.TypeUrl, Id: id, Data: data}
}

func assertExists(t *testing.T, srv databroker.Server, id string) {
	t.Helper()

	res, err := srv.Get(t.Context(), &databrokerpb.GetRequest{Type: singleflightRecordType(), Id: id})
	assert.NoError(t, err)
	assert.Equal(t, id, res.GetRecord().GetId())
}

func assertMissing(t *testing.T, srv databroker.Server, id string) {
	t.Helper()

	_, err := srv.Get(t.Context(), &databrokerpb.GetRequest{Type: singleflightRecordType(), Id: id})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestSingleflight(t *testing.T) {
	t.Parallel()

	t.Run("commit", func(t *testing.T) {
		srv, client := newSingleflightServer(t)

		shared, err := databrokerutil.Do(t.Context(), client, "commit", func(tx databrokerutil.Transaction) error {
			res, err := tx.Put(singleflightRecord("commit-1"), singleflightRecord("commit-2"))
			if err != nil {
				return err
			}
			assert.Len(t, res.GetRecords(), 2)
			return nil
		})
		require.NoError(t, err)
		assert.False(t, shared)

		assertExists(t, srv, "commit-1")
		assertExists(t, srv, "commit-2")
	})

	t.Run("read your writes", func(t *testing.T) {
		_, client := newSingleflightServer(t)

		shared, err := databrokerutil.Do(t.Context(), client, "ryw", func(tx databrokerutil.Transaction) error {
			if _, err := tx.Put(singleflightRecord("ryw-1")); err != nil {
				return err
			}
			res, err := tx.Get(singleflightRecordType(), "ryw-1")
			if err != nil {
				return err
			}
			assert.Equal(t, "ryw-1", res.GetRecord().GetId())
			return nil
		})
		require.NoError(t, err)
		assert.False(t, shared)
	})

	t.Run("rollback", func(t *testing.T) {
		srv, client := newSingleflightServer(t)

		rollback := errors.New("rollback")
		shared, err := databrokerutil.Do(t.Context(), client, "rollback", func(tx databrokerutil.Transaction) error {
			if _, err := tx.Put(singleflightRecord("rollback-1")); err != nil {
				return err
			}
			return rollback
		})
		assert.ErrorIs(t, err, rollback)
		assert.False(t, shared)

		assertMissing(t, srv, "rollback-1")
	})

	t.Run("shared", func(t *testing.T) {
		srv, client := newSingleflightServer(t)

		held, release := make(chan struct{}), make(chan struct{})
		holder := make(chan error, 1)
		go func() {
			_, err := databrokerutil.Do(t.Context(), client, "shared", func(tx databrokerutil.Transaction) error {
				close(held)
				<-release
				_, err := tx.Put(singleflightRecord("holder"))
				return err
			})
			holder <- err
		}()
		<-held

		sharedC := make(chan bool, 1)
		go func() {
			ran := false
			shared, err := databrokerutil.Do(t.Context(), client, "shared", func(tx databrokerutil.Transaction) error {
				ran = true
				_, err := tx.Put(singleflightRecord("suppressed"))
				return err
			})
			assert.NoError(t, err)
			assert.False(t, ran, "work should not run for a suppressed transaction")
			sharedC <- shared
		}()

		close(release)
		require.NoError(t, <-holder)
		assert.True(t, <-sharedC)

		assertExists(t, srv, "holder")
	})

	t.Run("shared client timeout does not cancel", func(t *testing.T) {
		srv, client := newSingleflightServer(t)

		held, release := make(chan struct{}), make(chan struct{})
		holder := make(chan error, 1)
		go func() {
			_, err := databrokerutil.Do(t.Context(), client, "timeout", func(tx databrokerutil.Transaction) error {
				close(held)
				<-release
				_, err := tx.Put(singleflightRecord("timeout-holder"))
				return err
			})
			holder <- err
		}()
		<-held

		waiterCtx, cancelWaiter := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancelWaiter()
		_, err := databrokerutil.Do(waiterCtx, client, "timeout", func(databrokerutil.Transaction) error {
			assert.Fail(t, "work should not run for a shared transaction")
			return nil
		})
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))

		// the holder is unaffected by the suppressed client giving up
		close(release)
		require.NoError(t, <-holder)
		assertExists(t, srv, "timeout-holder")
	})

	t.Run("after transaction done", func(t *testing.T) {
		_, client := newSingleflightServer(t)

		var escaped databrokerutil.Transaction
		_, err := databrokerutil.Do(t.Context(), client, "escaped", func(tx databrokerutil.Transaction) error {
			escaped = tx
			return nil
		})
		require.NoError(t, err)

		_, err = escaped.Put(singleflightRecord("escaped-1"))
		assert.ErrorIs(t, err, databrokerutil.ErrTransactionClosed)
	})

	t.Run("operation error", func(t *testing.T) {
		srv, client := newSingleflightServer(t)

		var opErr error
		shared, err := databrokerutil.Do(t.Context(), client, "op-error", func(tx databrokerutil.Transaction) error {
			if _, err := tx.Put(singleflightRecord("op-error-1")); err != nil {
				return err
			}
			// an empty operation is rejected by the backend, which fails the transaction
			_, opErr = tx(new(databrokerpb.TransactionRequest))
			return opErr
		})
		assert.Error(t, opErr)
		assert.Equal(t, opErr, err)
		assert.False(t, shared)

		assertMissing(t, srv, "op-error-1")
	})
}

// wireCounter tallies gRPC payload bytes on the client connection. The
// benchmarks run over bufconn, so this is protocol traffic rather than actual
// syscall-level IO.
type wireCounter struct {
	in, out atomic.Int64
}

func (c *wireCounter) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context { return ctx }

func (c *wireCounter) HandleRPC(_ context.Context, rs stats.RPCStats) {
	switch rs := rs.(type) {
	case *stats.InPayload:
		c.in.Add(int64(rs.WireLength))
	case *stats.OutPayload:
		c.out.Add(int64(rs.WireLength))
	}
}

func (c *wireCounter) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context { return ctx }

func (c *wireCounter) HandleConn(context.Context, stats.ConnStats) {}

type keyFunc func() string

type benchmarkOptions struct {
	storage func(testing.TB) config.DataBrokerOptions
	work    func(keyFunc) func(tx databrokerutil.Transaction) error
}

type singleflightBench struct {
	b           *testing.B
	ctx         context.Context
	server      databroker.Server
	client      databrokerpb.DataBrokerServiceClient
	wire        *wireCounter
	concurrency int
	key         func(iter, worker int) string
	work        func(keyFunc) func(tx databrokerutil.Transaction) error

	wg               sync.WaitGroup
	ran, sharedCount atomic.Int64
	before, after    runtime.MemStats
}

func newSingleflightBench(b *testing.B, concurrency int, key func(iter, worker int) string, opts benchmarkOptions) *singleflightBench {
	b.Helper()

	if opts.storage == nil {
		opts.storage = memoryStorage
	}
	if opts.work == nil {
		opts.work = func(k keyFunc) func(tx databrokerutil.Transaction) error {
			return func(tx databrokerutil.Transaction) error {
				_, err := tx.Put(singleflightRecord(k()))
				return err
			}
		}
	}

	s := &singleflightBench{
		b:           b,
		ctx:         b.Context(),
		wire:        new(wireCounter),
		concurrency: concurrency,
		key:         key,
		work:        opts.work,
	}
	s.server, s.client = newSingleflightServerFor(b, opts.storage(b), grpc.WithStatsHandler(s.wire))

	runtime.GC()
	runtime.ReadMemStats(&s.before)
	b.ReportAllocs()

	return s
}

// start launches one worker; hold, when non-nil, blocks it inside its
// transaction so callers can keep the flight open.
func (s *singleflightBench) start(iter, worker int, hold func()) {
	s.wg.Go(func() {
		k := s.key(iter, worker)
		body := s.work(func() string { return k })
		shared, err := databrokerutil.Do(s.ctx, s.client, k, func(tx databrokerutil.Transaction) error {
			s.ran.Add(1)
			if hold != nil {
				hold()
			}
			return body(tx)
		})
		if err != nil {
			s.b.Error(err)
		}
		if shared {
			s.sharedCount.Add(1)
		}
	})
}

func (s *singleflightBench) report() {
	s.b.StopTimer()

	runtime.GC()

	runtime.ReadMemStats(&s.after)
	ops := float64(s.b.N * s.concurrency)
	s.b.ReportMetric(float64(s.sharedCount.Load())/ops, "shared/op")
	s.b.ReportMetric(float64(s.wire.out.Load())/ops, "wire-out-B/op")
	s.b.ReportMetric(float64(s.wire.in.Load())/ops, "wire-in-B/op")
	s.b.ReportMetric(float64(s.after.TotalAlloc-s.before.TotalAlloc)/ops, "heap-B/op")
	s.b.ReportMetric(float64(s.after.HeapInuse-s.before.HeapInuse)/(1<<20), "heap-inuse-MB")
	s.b.ReportMetric(float64(s.after.Sys)/(1<<20), "sys-MB")
}

// benchmarkConcurrent starts every worker at once and leaves whether they
// overlap up to the scheduler.
func benchmarkConcurrent(b *testing.B, concurrency int, key func(iter, worker int) string, opts benchmarkOptions) {
	b.Helper()

	s := newSingleflightBench(b, concurrency, key, opts)
	for iter := 0; b.Loop(); iter++ {
		for worker := range concurrency {
			s.start(iter, worker, nil)
		}
		s.wg.Wait()
	}
	s.server.Stop()
	s.report()
}

// benchmarkConflicting opens a transaction first and only starts the remaining
// workers once it is in flight, so a round is one real transaction and N-1
// sharers. A straggler that reaches the server after the holder commits starts
// a flight of its own, so shared/op reports what was actually achieved.
func benchmarkConflicting(b *testing.B, concurrency int, key func(iter, worker int) string, opts benchmarkOptions) {
	b.Helper()

	s := newSingleflightBench(b, concurrency, key, opts)
	for iter := 0; b.Loop(); iter++ {
		held, release := make(chan struct{}), make(chan struct{})
		s.start(iter, 0, func() {
			close(held)
			<-release
		})
		<-held

		for worker := 1; worker < concurrency; worker++ {
			s.start(iter, worker, nil)
		}
		close(release)

		s.wg.Wait()
	}
	s.report()
}

func BenchmarkSingleFlight(b *testing.B) {

	restore := log.GetLevel()
	log.SetLevel(zerolog.Disabled)
	b.Cleanup(func() { log.SetLevel(restore) })

	startPostgres := sync.OnceValue(func() string { return testutil.StartPostgres(b) })

	stores := []struct {
		name    string
		options func(testing.TB) config.DataBrokerOptions
	}{
		{"mem", memoryStorage},
		{"file", fileStorage},
		{"postgres", postgresStorage(startPostgres)},
	}
	for _, storage := range stores {
		b.Run(storage.name, func(b *testing.B) {
			concurrency := 1
			for range 3 {
				concurrency *= 2
				b.Run(fmt.Sprintf("conc-%d", concurrency), func(b *testing.B) {
					opts := benchmarkOptions{storage: storage.options}

					b.Run("concurrent maybe conflicting", func(b *testing.B) {
						benchmarkConcurrent(b, concurrency, func(iter, _ int) string {
							return fmt.Sprintf("conflicting-%d", iter)
						}, opts)
					})

					// every worker contends for the same transaction, so all but one is shared
					b.Run("concurrent conflicting", func(b *testing.B) {
						benchmarkConflicting(b, concurrency, func(iter, _ int) string {
							return fmt.Sprintf("conflicting-%d", iter)
						}, opts)
					})

					// every worker gets its own key, so all transactions run for real
					b.Run("concurrent non-conflicting", func(b *testing.B) {
						benchmarkConcurrent(b, concurrency, func(iter, worker int) string {
							return fmt.Sprintf("non-conflicting-%d-%d", iter, worker)
						}, opts)
					})
				})
			}
		})
	}
}
