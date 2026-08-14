package databrokerutil_test

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/structpb"

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
	dir := t.TempDir()
	t.Cleanup(func() {
		assert.NoError(t, os.RemoveAll(dir))
	})

	return config.DataBrokerOptions{
		StorageType:             config.StorageFileName,
		StorageConnectionString: "file://" + dir,
	}
}

// postgresStorage hands every cluster its own database on one shared container,
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

		changed, shared, err := databrokerutil.Do(t.Context(), client, "commit", func(op databrokerutil.TX) error {
			res, err := op.Put(t.Context(), &databrokerpb.PutRequest{
				Records: []*databrokerpb.Record{singleflightRecord("commit-1"), singleflightRecord("commit-2")},
			})
			if err != nil {
				return err
			}
			assert.Len(t, res.GetRecords(), 2)
			return nil
		})
		require.NoError(t, err)
		assert.False(t, shared)
		assert.Len(t, changed, 2)

		assertExists(t, srv, "commit-1")
		assertExists(t, srv, "commit-2")
	})

	t.Run("operations return their underlying storage errors", func(t *testing.T) {
		srv, client := newSingleflightServer(t)
		changed, shared, err := databrokerutil.Do(t.Context(), client, "absent-check", func(tx databrokerutil.TX) error {
			_, err := tx.Get(t.Context(), &databrokerpb.GetRequest{
				Type: singleflightRecordType(),
				Id:   "absent",
			})
			assert.Error(t, err)
			assert.Equal(t, codes.NotFound, status.Code(err))

			resp, err := tx.Put(t.Context(), &databrokerpb.PutRequest{
				Records: []*databrokerpb.Record{
					singleflightRecord("absent"),
				},
			})
			assert.NoError(t, err)
			assert.Equal(t, len(resp.GetRecords()), 1)
			return nil
		})
		assert.NoError(t, err)
		assert.False(t, shared)
		assert.Equal(t, len(changed), 1)
		assertExists(t, srv, "absent")
	})

	t.Run("read your writes", func(t *testing.T) {
		_, client := newSingleflightServer(t)

		_, shared, err := databrokerutil.Do(t.Context(), client, "ryw", func(op databrokerutil.TX) error {
			if _, err := op.Put(t.Context(), &databrokerpb.PutRequest{
				Records: []*databrokerpb.Record{singleflightRecord("ryw-1")},
			}); err != nil {
				return err
			}
			res, err := op.Get(t.Context(), &databrokerpb.GetRequest{
				Type: singleflightRecordType(),
				Id:   "ryw-1",
			})
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
		_, shared, err := databrokerutil.Do(t.Context(), client, "rollback", func(op databrokerutil.TX) error {
			if _, err := op.Put(t.Context(), &databrokerpb.PutRequest{
				Records: []*databrokerpb.Record{singleflightRecord("rollback-1")},
			}); err != nil {
				return err
			}
			return rollback
		})
		assert.ErrorIs(t, err, rollback)
		assert.False(t, shared)

		assertMissing(t, srv, "rollback-1")
	})

	t.Run("shared", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			srv, client := newSingleflightServer(t)

			held, release := make(chan struct{}), make(chan struct{})
			holder := make(chan error, 1)
			go func() {
				_, _, err := databrokerutil.Do(t.Context(), client, "shared", func(op databrokerutil.TX) error {
					close(held)
					<-release
					_, err := op.Put(t.Context(), &databrokerpb.PutRequest{
						Records: []*databrokerpb.Record{singleflightRecord("holder")},
					})
					return err
				})
				holder <- err
			}()
			<-held

			sharedC := make(chan bool, 1)
			go func() {
				ran := false
				_, shared, err := databrokerutil.Do(t.Context(), client, "shared", func(op databrokerutil.TX) error {
					ran = true
					_, err := op.Put(t.Context(), &databrokerpb.PutRequest{
						Records: []*databrokerpb.Record{singleflightRecord("shared")},
					})
					return err
				})
				assert.NoError(t, err)
				assert.False(t, ran, "work should not run for a shared transaction")
				sharedC <- shared
			}()
			// the waiter only shares the flight if the server sees its begin before
			// the holder commits, so block until it is parked on the held key
			synctest.Wait()

			close(release)
			require.NoError(t, <-holder)
			assert.True(t, <-sharedC)

			assertExists(t, srv, "holder")
		})
	})

	t.Run("shared client timeout does not cancel", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			srv, client := newSingleflightServer(t)

			held, release := make(chan struct{}), make(chan struct{})
			holder := make(chan error, 1)
			go func() {
				_, _, err := databrokerutil.Do(t.Context(), client, "timeout", func(op databrokerutil.TX) error {
					close(held)
					<-release
					_, err := op.Put(t.Context(), &databrokerpb.PutRequest{
						Records: []*databrokerpb.Record{singleflightRecord("timeout-holder")},
					})
					return err
				})
				holder <- err
			}()
			<-held

			// the timeout runs on synctest's fake clock, so it can only elapse once
			// the waiter is parked on the held key
			waiterCtx, cancelWaiter := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancelWaiter()
			_, _, err := databrokerutil.Do(waiterCtx, client, "timeout", func(databrokerutil.TX) error {
				assert.Fail(t, "work should not run for a shared transaction")
				return nil
			})
			assert.Equal(t, codes.DeadlineExceeded, status.Code(err))

			// the holder is unaffected by the shared client giving up
			close(release)
			require.NoError(t, <-holder)
			assertExists(t, srv, "timeout-holder")
		})
	})

	t.Run("after transaction done", func(t *testing.T) {
		_, client := newSingleflightServer(t)

		var escaped databrokerutil.TX
		_, _, err := databrokerutil.Do(t.Context(), client, "escaped", func(op databrokerutil.TX) error {
			escaped = op
			return nil
		})
		require.NoError(t, err)

		_, err = escaped.Put(t.Context(), &databrokerpb.PutRequest{
			Records: []*databrokerpb.Record{singleflightRecord("escaped-1")},
		})
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	})

	t.Run("operation error", func(t *testing.T) {
		srv, client := newSingleflightServer(t)

		var opErr error
		_, shared, err := databrokerutil.Do(t.Context(), client, "op-error", func(op databrokerutil.TX) error {
			if _, err := op.Put(t.Context(), &databrokerpb.PutRequest{
				Records: []*databrokerpb.Record{singleflightRecord("op-error-1")},
			}); err != nil {
				return err
			}
			// an invalid query filter is rejected by the backend, which fails the transaction
			_, opErr = op.Query(t.Context(), &databrokerpb.QueryRequest{
				Type: singleflightRecordType(),
				Filter: &structpb.Struct{Fields: map[string]*structpb.Value{
					"$or": structpb.NewStringValue("not-an-array"),
				}},
			})
			return opErr
		})
		assert.Equal(t, codes.InvalidArgument, status.Code(opErr))
		assert.Equal(t, opErr, err)
		assert.False(t, shared)

		assertMissing(t, srv, "op-error-1")
	})
}

func BenchmarkSingleFlight_Concurrent(b *testing.B) {
	restore := log.GetLevel()
	log.SetLevel(zerolog.Disabled)
	b.Cleanup(func() { log.SetLevel(restore) })

	transport := parseTransport(b)
	replicas := parseReplicas(b)
	concurrency := parseConcurrency(b)

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
			b.Run(transport.String(), func(b *testing.B) {
				benchmarkConcurrent(b, func(iter, worker int) string {
					return fmt.Sprintf("non-conflicting-%d-%d", iter, worker)
				}, benchmarkOptions{
					storage:     storage.options,
					replicas:    replicas,
					transport:   transport,
					concurrency: concurrency,
				})
			})
		})
	}
}

func BenchmarkSingleFlight_ConcurrentConflicting(b *testing.B) {
	restore := log.GetLevel()
	log.SetLevel(zerolog.Disabled)
	b.Cleanup(func() { log.SetLevel(restore) })

	transport := parseTransport(b)
	replicas := parseReplicas(b)
	concurrency := parseConcurrency(b)

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
			b.Run(transport.String(), func(b *testing.B) {
				benchmarkConflicting(b, func(iter, _ int) string {
					return fmt.Sprintf("conflicting-%d", iter)
				}, benchmarkOptions{
					storage:     storage.options,
					replicas:    replicas,
					transport:   transport,
					concurrency: concurrency,
				})
			})
		})
	}
}

// wireCounter tallies gRPC payload bytes on the connections it is attached to.
// Under bufconn this is protocol traffic rather than syscall-level IO.
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
	storage     func(testing.TB) config.DataBrokerOptions
	work        func(keyFunc) func(op databrokerutil.TX) error
	replicas    int
	concurrency int
	transport   grpcTransport
}

type singleflightBench struct {
	b             *testing.B
	ctx           context.Context
	cluster       *cluster
	wire, fwdWire *wireCounter
	concurrency   int
	key           func(iter, worker int) string
	work          func(keyFunc) func(op databrokerutil.TX) error

	wg               sync.WaitGroup
	ran, sharedCount atomic.Int64
	before, after    runtime.MemStats
}

func newSingleflightBench(b *testing.B, concurrency int, key func(iter, worker int) string, opts benchmarkOptions) *singleflightBench {
	b.Helper()

	if opts.storage == nil {
		opts.storage = memoryStorage
	}
	if opts.replicas < 1 {
		opts.replicas = 1
	}
	if opts.work == nil {
		opts.work = func(k keyFunc) func(op databrokerutil.TX) error {
			return func(op databrokerutil.TX) error {
				_, err := op.Put(b.Context(), &databrokerpb.PutRequest{
					Records: []*databrokerpb.Record{singleflightRecord(k())},
				})
				return err
			}
		}
	}

	s := &singleflightBench{
		b:           b,
		ctx:         b.Context(),
		wire:        new(wireCounter),
		fwdWire:     new(wireCounter),
		concurrency: concurrency,
		key:         key,
		work:        opts.work,
	}
	s.cluster = newCluster(b, opts.storage(b), opts.replicas, opts.transport, s.wire, s.fwdWire)

	runtime.GC()
	runtime.ReadMemStats(&s.before)
	b.ReportAllocs()

	return s
}

// start launches one worker; hold, when non-nil, blocks it inside its
// transaction so callers can keep the flight open.
func (s *singleflightBench) start(iter, worker int, hold func()) {
	client := s.cluster.clients[worker%len(s.cluster.clients)]
	s.wg.Go(func() {
		k := s.key(iter, worker)
		body := s.work(func() string { return k })
		_, shared, err := databrokerutil.Do(s.ctx, client, k, func(op databrokerutil.TX) error {
			s.ran.Add(1)
			if hold != nil {
				hold()
			}
			return body(op)
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
	fwd := float64(s.fwdWire.in.Load() + s.fwdWire.out.Load())
	s.b.ReportMetric(float64(s.sharedCount.Load())/ops, "shared/op")
	s.b.ReportMetric(float64(s.wire.out.Load()+s.fwdWire.out.Load())/ops, "wire-out-B/op")
	s.b.ReportMetric(float64(s.wire.in.Load()+s.fwdWire.in.Load())/ops, "wire-in-B/op")
	s.b.ReportMetric(fwd/ops, "wire-fwd-B/op")
	s.b.ReportMetric(float64(s.after.TotalAlloc-s.before.TotalAlloc)/ops, "heap-B/op")
	s.b.ReportMetric(float64(s.after.HeapInuse-s.before.HeapInuse)/(1<<20), "heap-inuse-MB")
	s.b.ReportMetric(float64(s.after.Sys)/(1<<20), "sys-MB")
}

// benchmarkConcurrent starts every worker at once and leaves whether they
// overlap up to the scheduler.
func benchmarkConcurrent(b *testing.B, key func(iter, worker int) string, opts benchmarkOptions) {
	b.Helper()

	s := newSingleflightBench(b, opts.concurrency, key, opts)
	for iter := 0; b.Loop(); iter++ {
		for worker := range opts.concurrency {
			s.start(iter, worker, nil)
		}
		s.wg.Wait()
	}
	s.cluster.stop()
	s.report()
}

func benchmarkConflicting(b *testing.B, key func(iter, worker int) string, opts benchmarkOptions) {
	b.Helper()

	s := newSingleflightBench(b, opts.concurrency, key, opts)
	for iter := 0; b.Loop(); iter++ {
		held, release := make(chan struct{}), make(chan struct{})
		s.start(iter, 0, func() {
			close(held)
			<-release
		})
		<-held

		for worker := 1; worker < opts.concurrency; worker++ {
			s.start(iter, worker, nil)
		}
		close(release)

		s.wg.Wait()
	}
	s.report()
}

var (
	benchTransport = flag.String("singleflight.transport", "bufconn",
		"transport to benchmark: bufconn, tcp")
	benchReplicas = flag.Int("singleflight.replicas", 1,
		"servers per cluster")
	benchConcurrency = flag.Int("singleflight.concurrency", 8,
		"max concurrent in-flight transactions")
)

func parseTransport(b *testing.B) grpcTransport {
	b.Helper()

	switch *benchTransport {
	case "bufconn":
		return transportBufconn
	case "tcp":
		return transportTCP
	default:
		b.Fatalf("unknown transport %q", *benchTransport)
		return transportBufconn
	}
}

func parseReplicas(b *testing.B) int {
	b.Helper()

	if *benchReplicas < 1 {
		b.Fatalf("invalid replica count %d, must be greater than 0", *benchReplicas)
	}
	return *benchReplicas
}

func parseConcurrency(b *testing.B) int {
	b.Helper()

	if *benchConcurrency < 1 {
		b.Fatalf("invalid concurrency %d, must be greater than 0", *benchConcurrency)
	}
	return *benchConcurrency
}

type grpcTransport int

const (
	transportBufconn grpcTransport = iota
	transportTCP
)

func (tr grpcTransport) String() string {
	if tr == transportTCP {
		return "tcp"
	}
	return "bufconn"
}

type benchServer struct {
	b      *testing.B
	target string
	dial   func(context.Context, string) (net.Conn, error)
}

func startBenchServer(b *testing.B, transport grpcTransport, register func(s *grpc.Server)) *benchServer {
	b.Helper()

	srv := &benchServer{b: b}

	var li net.Listener
	switch transport {
	case transportTCP:
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(b, err)
		li = tcp
		srv.target = "passthrough:///" + tcp.Addr().String()
	default:
		bl := bufconn.Listen(1024 * 1024)
		li = bl
		srv.target = "passthrough://bufnet"
		srv.dial = func(context.Context, string) (net.Conn, error) {
			return bl.Dial()
		}
	}

	s := grpc.NewServer()
	register(s)
	go func() {
		err := s.Serve(li)
		if errors.Is(err, grpc.ErrServerStopped) {
			err = nil
		}
		require.NoError(b, err)
	}()
	b.Cleanup(s.Stop)

	return srv
}

func (srv *benchServer) dialClient(dialOpts ...grpc.DialOption) *grpc.ClientConn {
	srv.b.Helper()

	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	if srv.dial != nil {
		opts = append(opts, grpc.WithContextDialer(srv.dial))
	}
	opts = append(opts, dialOpts...)

	cc, err := grpc.NewClient(srv.target, opts...)
	require.NoError(srv.b, err)
	srv.b.Cleanup(func() {
		cc.Close()
	})

	return cc
}

func newBackend(t testing.TB, cfg *config.Config) databroker.Server {
	t.Helper()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), cfg)
	return srv
}

type cluster struct {
	servers []databroker.Server
	clients []databrokerpb.DataBrokerServiceClient
}

func newCluster(
	b *testing.B,
	storage config.DataBrokerOptions,
	replicas int,
	transport grpcTransport,
	wire, fwdWire *wireCounter,
) *cluster {
	b.Helper()

	cfg := config.New(&config.Options{DataBroker: storage, SharedKey: cryptutil.NewBase64Key()})
	sharedStorage := storage.StorageType == config.StoragePostgresName

	c := new(cluster)
	add := func(srv databroker.Server) *benchServer {
		gs := startBenchServer(b, transport, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, srv)
		})
		c.servers = append(c.servers, srv)
		c.clients = append(c.clients,
			databrokerpb.NewDataBrokerServiceClient(gs.dialClient(grpc.WithStatsHandler(wire))))
		return gs
	}

	leader := add(newBackend(b, cfg))
	if sharedStorage {
		_, err := c.servers[0].Get(b.Context(), &databrokerpb.GetRequest{
			Type: singleflightRecordType(),
			Id:   "migrate",
		})
		require.Equal(b, codes.NotFound, status.Code(err))
	}

	for range replicas - 1 {
		if sharedStorage {
			add(newBackend(b, cfg))
			continue
		}
		add(databroker.NewForwardingServer(leader.dialClient(grpc.WithStatsHandler(fwdWire))))
	}
	return c
}

func (c *cluster) stop() {
	for _, srv := range slices.Backward(c.servers) {
		srv.Stop()
	}
}
