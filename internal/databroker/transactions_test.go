package databroker

import (
	"context"
	"io"
	"testing"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

type transactionStream = grpc.BidiStreamingClient[databrokerpb.TransactionStreamRequest, databrokerpb.TransactionStreamResponse]

func newTransactionClient(t *testing.T, srv databrokerpb.DataBrokerServiceServer) databrokerpb.DataBrokerServiceClient {
	t.Helper()

	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})
	return databrokerpb.NewDataBrokerServiceClient(cc)
}

type transactionServersFunc func(t *testing.T) (Server, databrokerpb.DataBrokerServiceClient)

func newBackendServers(t *testing.T) (Server, databrokerpb.DataBrokerServiceClient) {
	srv := newServer(t)
	t.Cleanup(func() {
		srv.Stop()
	})
	return srv, newTransactionClient(t, srv)
}

func newFollowerServers(t *testing.T) (Server, databrokerpb.DataBrokerServiceClient) {
	leader := newServer(t)
	leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, leader)
	})
	follower := NewClusteredFollowerServer(noop.NewTracerProvider(), newServer(t), leaderCC)
	t.Cleanup(follower.Stop)
	return leader, newTransactionClient(t, follower)
}

func TestDatabrokerTransactions(t *testing.T) {
	t.Parallel()

	setups := []struct {
		name            string
		newServers      transactionServersFunc
		transactionType databrokerpb.TransactionType
	}{
		{"backend", newBackendServers, databrokerpb.TransactionType_TRANSACTION_TYPE_SINGLEFLIGHT},
		{"backend", newBackendServers, databrokerpb.TransactionType_TRANSACTION_TYPE_NOLOCK},
		{"clustered follower", newFollowerServers, databrokerpb.TransactionType_TRANSACTION_TYPE_SINGLEFLIGHT},
		{"clustered follower", newFollowerServers, databrokerpb.TransactionType_TRANSACTION_TYPE_NOLOCK},
	}
	for _, setup := range setups {
		t.Run(setup.name, func(t *testing.T) {
			testTransactions(t, setup.newServers, setup.transactionType)
		})
	}
}

func testTransactions(t *testing.T, newServers transactionServersFunc, transactionType databrokerpb.TransactionType) {
	if transactionType == databrokerpb.TransactionType_TRANSACTION_TYPE_UNKNOWN {
		assert.Fail(t, "expected transaction type to be valid")
	}
	t.Run("get put patch query", func(t *testing.T) {
		srv, client := newServers(t)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "operations", transactionType).GetBegin())

		sendOperation(t, stream, "operations", 1, putOperation(newTransactionRecord("op-1")))
		assert.Len(t, recvOperation(t, stream, "operations").GetPut().GetRecords(), 1)

		sendOperation(t, stream, "operations", 2, getOperation("op-1"))
		assert.Equal(t, "op-1", recvOperation(t, stream, "operations").GetGet().GetRecord().GetId())

		patched := newTransactionRecord("op-1")
		patched.Data = protoutil.NewAny(&sessionpb.Session{Id: "op-1", UserId: "user-1"})
		sendOperation(t, stream, "operations", 3, &databrokerpb.TransactionRequest{
			Operation: &databrokerpb.TransactionRequest_Patch{
				Patch: &databrokerpb.PatchRequest{
					Records:   []*databrokerpb.Record{patched},
					FieldMask: &fieldmaskpb.FieldMask{Paths: []string{"user_id"}},
				},
			},
		})
		assert.Len(t, recvOperation(t, stream, "operations").GetPatch().GetRecords(), 1)

		sendOperation(t, stream, "operations", 4, &databrokerpb.TransactionRequest{
			Operation: &databrokerpb.TransactionRequest_Query{
				Query: &databrokerpb.QueryRequest{Type: recordType(), Limit: 10},
			},
		})
		assert.NotNil(t, recvOperation(t, stream, "operations").GetQuery())

		sendCommit(t, stream, "operations")
		commit, err := recvCommit(t, stream, "operations")
		require.NoError(t, err)
		assert.False(t, commit.GetShared())

		assertRecordExists(t, srv, "op-1")
	})

	t.Run("returns storage errors to the caller", func(t *testing.T) {
		srv, client := newServers(t)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "storage-error", transactionType).GetBegin())

		sendOperation(t, stream, "storage-error", 1, getOperation("missing"))
		res, err := stream.Recv()
		require.NoError(t, err)
		assert.Equal(t, uint64(1), res.GetSequence())
		assert.Nil(t, res.GetOperation().GetResponse())
		assert.Equal(t, int32(codes.NotFound), res.GetOperation().GetErr().GetCode())

		// a failed operation does not end the transaction
		sendOperation(t, stream, "storage-error", 2, putOperation(newTransactionRecord("after-error")))
		assert.Len(t, recvOperation(t, stream, "storage-error").GetPut().GetRecords(), 1)

		sendCommit(t, stream, "storage-error")
		_, err = recvCommit(t, stream, "storage-error")
		require.NoError(t, err)

		assertRecordExists(t, srv, "after-error")
	})

	t.Run("rollback on closed stream", func(t *testing.T) {
		srv, client := newServers(t)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "stream-closed", transactionType).GetBegin())
		sendOperation(t, stream, "stream-closed", 1, putOperation(newTransactionRecord("stream-closed")))
		_, err = stream.Recv()
		require.NoError(t, err)
		require.NoError(t, stream.CloseSend())

		_, err = recvCommit(t, stream, "stream-closed")
		assert.Error(t, err)
		assert.NotErrorIs(t, err, io.EOF)

		assertRecordMissing(t, srv, "stream-closed")
	})

	t.Run("rollback on max duration exceeded", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			srv, client := newServers(t)

			stream, err := client.Transaction(t.Context())
			require.NoError(t, err)

			require.NotNil(t, beginTransaction(t, stream, "deadline", transactionType).GetBegin())
			sendOperation(t, stream, "deadline", 1, putOperation(newTransactionRecord("deadline")))
			_, err = stream.Recv()
			require.NoError(t, err)
			// the deadline runs on synctest's fake clock, so it can only elapse
			// while every goroutine is blocked waiting for the commit
			_, err = recvCommit(t, stream, "deadline")
			assert.Equal(t, codes.DeadlineExceeded, status.Code(err))

			assertRecordMissing(t, srv, "deadline")
		})
	})

	t.Run("rollback on backend internal error", func(t *testing.T) {
		srv, client := newServers(t)
		setBackend(t, srv, func(backend storage.Backend) storage.Backend {
			return &txErrStorageBackend{Backend: backend, failOnID: "error"}
		})

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "commit-error", transactionType).GetBegin())
		sendOperation(t, stream, "commit-error", 1, putOperation(newTransactionRecord("ok")))
		_, err = stream.Recv()
		require.NoError(t, err)

		sendOperation(t, stream, "commit-error", 2, putOperation(newTransactionRecord("error")))
		_, err = stream.Recv()
		require.NoError(t, err)

		sendCommit(t, stream, "commit-error")
		_, err = recvCommit(t, stream, "commit-error")
		assert.Equal(t, codes.Internal, status.Code(err))
		assert.ErrorContains(t, err, "error committing transaction")

		assertRecordMissing(t, srv, "ok")
		assertRecordMissing(t, srv, "error")
	})

	t.Run("rollback on cancel", func(t *testing.T) {
		srv, client := newServers(t)

		ctx, cancel := context.WithCancel(t.Context())
		stream, err := client.Transaction(ctx)
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "cancel", transactionType).GetBegin())
		sendOperation(t, stream, "cancel", 1, putOperation(newTransactionRecord("cancel-1")))
		_, err = stream.Recv()
		require.NoError(t, err)
		cancel()

		_, err = recvCommit(t, stream, "cancel")
		assert.Equal(t, codes.Canceled, status.Code(err))

		assertRecordMissing(t, srv, "cancel-1")
	})

	t.Run("first message must be begin", func(t *testing.T) {
		srv, client := newServers(t)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		sendOperation(t, stream, "no-begin", 1, putOperation(newTransactionRecord("no-begin-1")))

		_, err = recvCommit(t, stream, "no-begin")
		assert.Equal(t, codes.InvalidArgument, status.Code(err))

		assertRecordMissing(t, srv, "no-begin-1")
	})

	t.Run("second begin is rejected", func(t *testing.T) {
		srv, client := newServers(t)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "double-begin", transactionType).GetBegin())
		sendOperation(t, stream, "double-begin", 1, putOperation(newTransactionRecord("double-begin-1")))
		_, err = stream.Recv()
		require.NoError(t, err)
		sendBegin(t, stream, "double-begin", transactionType)

		_, err = recvCommit(t, stream, "double-begin")
		assert.Equal(t, codes.InvalidArgument, status.Code(err))

		assertRecordMissing(t, srv, "double-begin-1")
	})

	t.Run("messages for another key terminate the transaction", func(t *testing.T) {
		srv, client := newServers(t)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "commit-mismatch", transactionType).GetBegin())
		sendOperation(t, stream, "commit-mismatch", 1, putOperation(newTransactionRecord("commit-mismatch")))
		require.NotNil(t, recvOperation(t, stream, "commit-mismatch").GetPut())
		sendCommit(t, stream, "other-key")

		_, err = recvCommit(t, stream, "commit-mismatch")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))

		assertRecordMissing(t, srv, "commit-mismatch")
	})

	t.Run("messages for another key terminate the transaction", func(t *testing.T) {
		srv, client := newServers(t)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "commit-mismatch", transactionType).GetBegin())
		sendOperation(t, stream, "commit-mismatch", 1, putOperation(newTransactionRecord("commit-mismatch")))
		require.NotNil(t, recvOperation(t, stream, "commit-mismatch").GetPut())
		sendCommit(t, stream, "other-key")

		_, err = recvCommit(t, stream, "commit-mismatch")
		assert.Equal(t, codes.FailedPrecondition, status.Code(err))

		assertRecordMissing(t, srv, "commit-mismatch")
	})

	t.Run("singleflight held", func(t *testing.T) {
		if transactionType != databrokerpb.TransactionType_TRANSACTION_TYPE_SINGLEFLIGHT {
			t.Skip("dedupe test only applies to singleflight transactions")
		}
		synctest.Test(t, func(t *testing.T) {
			srv, client := newServers(t)

			// hold the key from the test side so the stream below certainly shares the result
			db, err := srv.(*backendServer).getBackend(t.Context())
			require.NoError(t, err)
			held, release := make(chan struct{}), make(chan struct{})
			holder := make(chan error, 1)
			go func() {
				_, _, err := db.DoTransaction(t.Context(), "shared-key", func(tx storage.Transaction) error {
					close(held)
					<-release
					_, err := tx.Submit(putOperation(newTransactionRecord("holder")))
					return err
				}, storage.WithTransactionType(transactionType))
				holder <- err
			}()
			<-held

			stream, err := client.Transaction(t.Context())
			require.NoError(t, err)
			sendBegin(t, stream, "shared-key", transactionType)
			sendOperation(t, stream, "shared-key", 1, putOperation(newTransactionRecord("shared")))

			responses := make(chan *databrokerpb.TransactionStreamResponse, 1)
			go func() {
				res, err := stream.Recv()
				if err == nil {
					responses <- res
				}
				close(responses)
			}()

			// the stream is parked in singleflight, so once everything else is
			// blocked no response can be in flight
			synctest.Wait()
			select {
			case res := <-responses:
				require.FailNow(t, "the sharing stream responded while the key was held", "%v", res)
			default:
			}

			close(release)
			require.NoError(t, <-holder)

			res, ok := <-responses
			require.True(t, ok)
			require.Nil(t, res.GetBegin(), "a shared transaction should not be acked")
			assert.True(t, res.GetCommit().GetShared())
			assert.Equal(t, "shared-key", res.GetCommit().GetKey())

			assertRecordExists(t, srv, "holder")
			assertRecordMissing(t, srv, "shared")

			next, err := client.Transaction(t.Context())
			require.NoError(t, err)
			require.NotNil(t, beginTransaction(t, next, "shared-key", transactionType).GetBegin())
			sendOperation(t, next, "shared-key", 1, getOperation("holder"))
			assert.Equal(t, "holder", recvOperation(t, next, "shared-key").GetGet().GetRecord().GetId())

			sendOperation(t, next, "shared-key", 2, putOperation(newTransactionRecord("next")))
			recvOperation(t, next, "shared-key")
			sendCommit(t, next, "shared-key")

			nextCommit, err := recvCommit(t, next, "shared-key")
			require.NoError(t, err)
			assert.False(t, nextCommit.GetShared())
			assertRecordExists(t, srv, "next")
		})
	})

	t.Run("sequence echoes", func(t *testing.T) {
		_, client := newServers(t)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "sequence", transactionType).GetBegin())

		sequences := []uint64{7, 3, 9}
		for i, sequence := range sequences {
			sendOperation(t, stream, "sequence", sequence, putOperation(newTransactionRecord(string(rune('a'+i)))))
		}
		for _, sequence := range sequences {
			res, err := stream.Recv()
			require.NoError(t, err)
			assert.Equal(t, sequence, res.GetSequence())
		}

		sendCommit(t, stream, "sequence")
		_, err = recvCommit(t, stream, "sequence")
		require.NoError(t, err)
	})

	t.Run("backend closure", func(t *testing.T) {
		server, client := newServers(t)
		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)
		require.NotNil(t, beginTransaction(t, stream, "reload", transactionType).GetBegin())
		sendOperation(t, stream, "reload", 1, putOperation(newTransactionRecord("record-1")))
		require.NotNil(t, recvOperation(t, stream, "reload").GetPut())

		// hack
		bs := server.(*backendServer)
		bs.mu.Lock()
		bs.closeBackendLocked(t.Context())
		bs.mu.Unlock()
		// end hack

		sendCommit(t, stream, "reload")
		_, err = recvCommit(t, stream, "reload")
		require.Error(t, err)
		assertRecordMissing(t, server, "record-1")
	})
}

func setBackend(t *testing.T, srv Server, wrap func(storage.Backend) storage.Backend) {
	t.Helper()

	bs, ok := srv.(*backendServer)
	require.True(t, ok)

	backend, err := bs.getBackend(t.Context())
	require.NoError(t, err)

	bs.mu.Lock()
	bs.backend = wrap(backend)
	bs.mu.Unlock()
}

type txErrStorageBackend struct {
	storage.Backend
	failOnID string
}

func (b *txErrStorageBackend) DoTransaction(ctx context.Context, key string, fn func(tx storage.Transaction) error, opts ...storage.TransactionOption) (
	changed []*databrokerpb.Record,
	shared bool,
	err error,
) {
	return b.Backend.DoTransaction(ctx, key, func(tx storage.Transaction) error {
		failing := &txErrTransaction{Transaction: tx, failOnID: b.failOnID}
		if err := fn(failing); err != nil {
			return err
		}
		if failing.doomed {
			return status.Error(codes.Internal, "error committing transaction")
		}
		return nil
	}, opts...)
}

type txErrTransaction struct {
	storage.Transaction
	failOnID string
	doomed   bool
}

func (tx *txErrTransaction) Submit(req *databrokerpb.TransactionRequest) (*databrokerpb.TransactionResponse, error) {
	for _, record := range req.GetPut().GetRecords() {
		if record.GetId() == tx.failOnID {
			tx.doomed = true
		}
	}
	return tx.Transaction.Submit(req)
}

func newTransactionRecord(id string) *databrokerpb.Record {
	data := protoutil.NewAny(&sessionpb.Session{Id: id})
	return &databrokerpb.Record{Type: data.TypeUrl, Id: id, Data: data}
}

func recordType() string {
	return protoutil.NewAny(new(sessionpb.Session)).TypeUrl
}

func sendBegin(t *testing.T, stream transactionStream, key string, typ databrokerpb.TransactionType) {
	t.Helper()

	require.NoError(t, stream.Send(&databrokerpb.TransactionStreamRequest{
		Message: &databrokerpb.TransactionStreamRequest_Begin{
			Begin: &databrokerpb.BeginTransaction{
				Key:  key,
				Type: typ,
			},
		},
	}))
}

// beginTransaction sends begin and reads the response saying whether this
// transaction is running (begin arm) or shares another transaction's result (commit arm).
func beginTransaction(t *testing.T, stream transactionStream, key string, typ databrokerpb.TransactionType) *databrokerpb.TransactionStreamResponse {
	t.Helper()

	sendBegin(t, stream, key, typ)
	res, err := stream.Recv()
	require.NoError(t, err)
	if begin := res.GetBegin(); begin != nil {
		assert.Equal(t, key, begin.GetKey())
	}
	if commit := res.GetCommit(); commit != nil {
		assert.Equal(t, key, commit.GetKey())
	}
	return res
}

func sendOperation(t *testing.T, stream transactionStream, key string, sequence uint64, op *databrokerpb.TransactionRequest) {
	t.Helper()

	op.Key = key
	require.NoError(t, stream.Send(&databrokerpb.TransactionStreamRequest{
		Sequence: sequence,
		Message:  &databrokerpb.TransactionStreamRequest_Operation{Operation: op},
	}))
}

func sendCommit(t *testing.T, stream transactionStream, key string) {
	t.Helper()

	require.NoError(t, stream.Send(&databrokerpb.TransactionStreamRequest{
		Message: &databrokerpb.TransactionStreamRequest_Commit{
			Commit: &databrokerpb.CommitTransaction{Key: key},
		},
	}))
}

func putOperation(records ...*databrokerpb.Record) *databrokerpb.TransactionRequest {
	return &databrokerpb.TransactionRequest{
		Operation: &databrokerpb.TransactionRequest_Put{
			Put: &databrokerpb.PutRequest{Records: records},
		},
	}
}

func getOperation(id string) *databrokerpb.TransactionRequest {
	return &databrokerpb.TransactionRequest{
		Operation: &databrokerpb.TransactionRequest_Get{
			Get: &databrokerpb.GetRequest{Type: recordType(), Id: id},
		},
	}
}

// recvOperation reads an operation response and asserts the operation itself did not fail.
func recvOperation(t *testing.T, stream transactionStream, key string) *databrokerpb.TransactionResponse {
	t.Helper()

	res, err := stream.Recv()
	require.NoError(t, err)
	require.Nil(t, res.GetOperation().GetErr())
	assert.Equal(t, key, res.GetOperation().GetResponse().GetKey())
	return res.GetOperation().GetResponse()
}

// recvCommit reads responses until the commit arm arrives, ignoring operation responses.
func recvCommit(t *testing.T, stream transactionStream, key string) (*databrokerpb.CommitTransactionResponse, error) {
	t.Helper()

	for {
		res, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		if commit := res.GetCommit(); commit != nil {
			assert.Equal(t, key, commit.GetKey())
			return commit, nil
		}
	}
}

func assertRecordExists(t *testing.T, srv Server, id string) {
	t.Helper()

	res, err := srv.Get(t.Context(), &databrokerpb.GetRequest{Type: recordType(), Id: id})
	assert.NoError(t, err)
	assert.Equal(t, id, res.GetRecord().GetId())
}

func assertRecordMissing(t *testing.T, srv Server, id string) {
	t.Helper()

	_, err := srv.Get(t.Context(), &databrokerpb.GetRequest{Type: recordType(), Id: id})
	assert.Equal(t, codes.NotFound, status.Code(err))
}
