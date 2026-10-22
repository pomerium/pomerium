package postgres

import (
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func TestDeleteDeadlock(t *testing.T) {
	t.Skip("this test is not reliable")

	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	tm1 := time.Date(2025, 7, 23, 13, 39, 0, 0, time.Local)

	ctx := t.Context()

	dsn := testutil.StartPostgres(t)
	conn1, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn1.Close(ctx)
	_, err = conn1.Exec(ctx, `SET lock_timeout TO 10`)
	require.NoError(t, err)

	conn2, err := pgx.Connect(ctx, dsn)
	require.NoError(t, err)
	defer conn2.Close(ctx)
	_, err = conn2.Exec(ctx, `SET lock_timeout TO 10`)
	require.NoError(t, err)

	require.NoError(t, pgx.BeginTxFunc(ctx, conn1, pgx.TxOptions{AccessMode: pgx.ReadWrite},
		func(tx pgx.Tx) error {
			_, err := migrate(ctx, tx)
			return err
		}))
	var version atomic.Uint64

	for range 10 {
		require.NoError(t, putRecordAndChange(ctx, conn1, &databroker.Record{
			Type:       "example",
			Version:    version.Add(1),
			Id:         uuid.NewString(),
			Data:       protoutil.NewAnyString("example"),
			ModifiedAt: timestamppb.New(tm1),
			DeletedAt:  timestamppb.New(tm1),
		}, false))
	}

	tx1, err := conn1.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.Serializable,
		AccessMode: pgx.ReadWrite,
	})
	require.NoError(t, err)

	tx2, err := conn2.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.Serializable,
		AccessMode: pgx.ReadWrite,
	})
	require.NoError(t, err)

	eg, ectx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return deleteChangesBefore(ectx, tx1, tm1.Add(time.Minute))
	})
	eg.Go(func() error {
		return deleteChangesBefore(ectx, tx2, tm1.Add(time.Minute))
	})
	require.NoError(t, eg.Wait())

	require.NoError(t, tx1.Commit(ctx))
	require.NoError(t, tx2.Commit(ctx))
}

// TestPutIfMatchVersionCoordinatesWithOrdinaryCreate forces an ordinary Put
// to hold an uncommitted insert while a conditional create (version 0)
// observes the key as absent. The conditional write must not silently
// overwrite the committed ordinary value.
func TestPutIfMatchVersionCoordinatesWithOrdinaryCreate(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const recordType = "if-match-race-test"
	backend, blockedSessions, unlockGate := startGatedBackend(t, "INSERT", recordType)

	newRecord := func(value string) *databroker.Record {
		return &databroker.Record{
			Type: recordType,
			Id:   "1",
			Data: protoutil.NewAny(protoutil.NewStructMap(map[string]*structpb.Value{
				"value": protoutil.NewStructString(value),
			})),
		}
	}

	ordinaryDone := make(chan error, 1)
	go func() {
		_, err := backend.Put(ctx, []*databroker.Record{newRecord("ordinary")})
		ordinaryDone <- err
	}()
	require.Eventually(t, func() bool { return blockedSessions() >= 1 }, 10*time.Second, 10*time.Millisecond)

	conditionalDone := make(chan error, 1)
	go func() {
		// version 0: create only if absent
		_, err := backend.Put(ctx, []*databroker.Record{newRecord("conditional")}, storage.WithIfMatchVersion())
		conditionalDone <- err
	}()
	require.Eventually(t, func() bool { return blockedSessions() >= 2 }, 10*time.Second, 10*time.Millisecond)

	unlockGate()
	require.NoError(t, <-ordinaryDone)

	conditionalErr := <-conditionalDone
	if conditionalErr != nil {
		require.ErrorIs(t, conditionalErr, databroker.ErrRecordVersionMismatch)
	}

	record, err := backend.Get(ctx, recordType, "1")
	require.NoError(t, err)
	var value structpb.Value
	require.NoError(t, record.GetData().UnmarshalTo(&value))
	assert.Equal(t, "ordinary", value.GetStructValue().GetFields()["value"].GetStringValue(),
		"the committed ordinary value must not be overwritten by a create-if-absent")
}

// TestPutIfMatchVersionLosesToConcurrentDelete forces an ordinary delete to
// hold an uncommitted delete while a conditional update at the version last
// read waits on the same row. Once the delete commits, the conditional write
// must fail as a mismatch rather than re-create the record.
func TestPutIfMatchVersionLosesToConcurrentDelete(t *testing.T) {
	t.Parallel()

	ctx := t.Context()
	const recordType = "if-match-delete-race-test"
	backend, blockedSessions, unlockGate := startGatedBackend(t, "DELETE", recordType)

	records := []*databroker.Record{{Type: recordType, Id: "1", Data: protoutil.NewAnyString("v1")}}
	_, err := backend.Put(ctx, records)
	require.NoError(t, err)
	read := records[0].GetVersion()

	deleteDone := make(chan error, 1)
	go func() {
		_, err := backend.Put(ctx, []*databroker.Record{
			{Type: recordType, Id: "1", DeletedAt: timestamppb.Now()},
		})
		deleteDone <- err
	}()
	require.Eventually(t, func() bool { return blockedSessions() >= 1 }, 10*time.Second, 10*time.Millisecond)

	conditionalDone := make(chan error, 1)
	go func() {
		_, err := backend.Put(ctx, []*databroker.Record{
			{Type: recordType, Id: "1", Version: read, Data: protoutil.NewAnyString("v2")},
		}, storage.WithIfMatchVersion())
		conditionalDone <- err
	}()
	require.Eventually(t, func() bool { return blockedSessions() >= 2 }, 10*time.Second, 10*time.Millisecond)

	unlockGate()
	require.NoError(t, <-deleteDone)
	assert.ErrorIs(t, <-conditionalDone, databroker.ErrRecordVersionMismatch)

	_, err = backend.Get(ctx, recordType, "1")
	assert.ErrorIs(t, err, storage.ErrNotFound,
		"a conditional update that lost to a delete must not re-create the record")
}

// startGatedBackend starts a backend whose records table has an AFTER event
// ("INSERT" or "DELETE") trigger that parks every such write of recordType on
// a gate, keeping it uncommitted until unlockGate is called. blockedSessions
// counts the sessions waiting on a lock.
func startGatedBackend(t *testing.T, event, recordType string) (backend *Backend, blockedSessions func() int, unlockGate func()) {
	t.Helper()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	ctx := t.Context()
	backend = New(ctx, testutil.StartPostgres(t))
	t.Cleanup(func() { _ = backend.Close() })

	_, pool, err := backend.init(ctx)
	require.NoError(t, err)

	const gateKey int64 = 2147483000
	gate, err := pool.Acquire(ctx)
	require.NoError(t, err)
	// if a test fails before unlocking the gate, cancelling the test context
	// unparks the waiting writes and closing the backend drops the gate
	t.Cleanup(gate.Release)
	_, err = gate.Exec(ctx, `SELECT pg_advisory_lock($1)`, gateKey)
	require.NoError(t, err)
	unlockGate = sync.OnceFunc(func() {
		_, err := gate.Exec(ctx, `SELECT pg_advisory_unlock($1)`, gateKey)
		assert.NoError(t, err)
	})

	row := "NEW"
	if event == "DELETE" {
		row = "OLD"
	}
	_, err = pool.Exec(ctx, `
		CREATE FUNCTION `+schemaName+`.block_write()
		RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
			IF `+row+`.type = '`+recordType+`' THEN
				PERFORM pg_advisory_xact_lock(`+strconv.FormatInt(gateKey, 10)+`);
			END IF;
			RETURN `+row+`;
		END $$;
		CREATE TRIGGER block_write
		AFTER `+event+` ON `+schemaName+`.`+recordsTableName+`
		FOR EACH ROW EXECUTE FUNCTION `+schemaName+`.block_write();
	`)
	require.NoError(t, err)

	blockedSessions = func() int {
		var count int
		err := pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database() AND wait_event_type = 'Lock'
		`).Scan(&count)
		require.NoError(t, err)
		return count
	}
	return backend, blockedSessions, unlockGate
}
