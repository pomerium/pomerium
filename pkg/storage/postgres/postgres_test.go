package postgres

import (
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestDeleteDeadlock(t *testing.T) {
	t.Parallel()

	if os.Getenv("GITHUB_ACTION") != "" && runtime.GOOS == "darwin" {
		t.Skip("Github action can not run docker on MacOS")
	}

	tm1 := time.Date(2025, 7, 23, 13, 39, 0, 0, time.Local)

	ctx := t.Context()
	testutil.WithTestPostgres(t, func(dsn string) {
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
		var version uint64

		for range 10 {
			require.NoError(t, putRecordAndChange(ctx, conn1, &databroker.Record{
				Type:       "example",
				Version:    atomic.AddUint64(&version, 1),
				Id:         uuid.NewString(),
				Data:       protoutil.NewAnyString("example"),
				ModifiedAt: timestamppb.New(tm1),
				DeletedAt:  timestamppb.New(tm1),
			}))
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
	})
}
