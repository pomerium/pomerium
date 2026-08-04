package databrokerutil_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func newSingleflightServer(t *testing.T) (databroker.Server, databrokerpb.DataBrokerServiceClient) {
	t.Helper()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	srv.OnConfigChange(t.Context(), config.New(&config.Options{
		DataBroker: config.DataBrokerOptions{StorageType: config.StorageInMemoryName},
		SharedKey:  cryptutil.NewBase64Key(),
	}))

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})
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
