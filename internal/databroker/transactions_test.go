package databroker

import (
	"context"
	"encoding/base64"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	sessionpb "github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
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

func newTransactionRecord(id string) *databrokerpb.Record {
	data := protoutil.NewAny(&sessionpb.Session{Id: id})
	return &databrokerpb.Record{Type: data.TypeUrl, Id: id, Data: data}
}

func recordType() string {
	return protoutil.NewAny(new(sessionpb.Session)).TypeUrl
}

func sendBegin(t *testing.T, stream transactionStream, key string) {
	t.Helper()

	require.NoError(t, stream.Send(&databrokerpb.TransactionStreamRequest{
		Message: &databrokerpb.TransactionStreamRequest_Begin{
			Begin: &databrokerpb.BeginTransaction{Key: key},
		},
	}))
}

// beginTransaction sends begin and reads the response saying whether this
// transaction is running (begin arm) or was suppressed (commit arm).
func beginTransaction(t *testing.T, stream transactionStream, key string) *databrokerpb.TransactionStreamResponse {
	t.Helper()

	sendBegin(t, stream, key)
	res, err := stream.Recv()
	require.NoError(t, err)
	return res
}

func sendOperation(t *testing.T, stream transactionStream, sequence uint64, op *databrokerpb.TransactionRequest) {
	t.Helper()

	require.NoError(t, stream.Send(&databrokerpb.TransactionStreamRequest{
		Sequence: sequence,
		Message:  &databrokerpb.TransactionStreamRequest_Operation{Operation: op},
	}))
}

func sendCommit(t *testing.T, stream transactionStream) {
	t.Helper()

	require.NoError(t, stream.Send(&databrokerpb.TransactionStreamRequest{
		Message: &databrokerpb.TransactionStreamRequest_Commit{
			Commit: new(databrokerpb.CommitTransaction),
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

// putInTransaction runs a whole begin/put/commit transaction and returns the commit response.
func putInTransaction(
	ctx context.Context,
	t *testing.T,
	client databrokerpb.DataBrokerServiceClient,
	key string,
	records ...*databrokerpb.Record,
) *databrokerpb.CommitTransactionResponse {
	t.Helper()

	stream, err := client.Transaction(ctx)
	require.NoError(t, err)

	sendBegin(t, stream, key)
	sendOperation(t, stream, 1, putOperation(records...))
	sendCommit(t, stream)

	commit, err := recvCommit(t, stream)
	require.NoError(t, err)
	return commit
}

// recvCommit reads responses until the commit arm arrives, ignoring operation responses.
func recvCommit(t *testing.T, stream transactionStream) (*databrokerpb.CommitTransactionResponse, error) {
	t.Helper()

	for {
		res, err := stream.Recv()
		if err != nil {
			return nil, err
		}
		if commit := res.GetCommit(); commit != nil {
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

func TestDatabrokerTransactions(t *testing.T) {
	t.Parallel()

	t.Run("operations", func(t *testing.T) {
		srv := newServer(t)
		client := newTransactionClient(t, srv)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "operations").GetBegin())

		sendOperation(t, stream, 1, putOperation(newTransactionRecord("op-1")))
		res, err := stream.Recv()
		require.NoError(t, err)
		assert.Len(t, res.GetOperation().GetPut().GetRecords(), 1)

		sendOperation(t, stream, 2, getOperation("op-1"))
		res, err = stream.Recv()
		require.NoError(t, err)
		assert.Equal(t, "op-1", res.GetOperation().GetGet().GetRecord().GetId())

		patched := newTransactionRecord("op-1")
		patched.Data = protoutil.NewAny(&sessionpb.Session{Id: "op-1", UserId: "user-1"})
		sendOperation(t, stream, 3, &databrokerpb.TransactionRequest{
			Operation: &databrokerpb.TransactionRequest_Patch{
				Patch: &databrokerpb.PatchRequest{
					Records:   []*databrokerpb.Record{patched},
					FieldMask: &fieldmaskpb.FieldMask{Paths: []string{"user_id"}},
				},
			},
		})
		res, err = stream.Recv()
		require.NoError(t, err)
		assert.Len(t, res.GetOperation().GetPatch().GetRecords(), 1)

		sendOperation(t, stream, 4, &databrokerpb.TransactionRequest{
			Operation: &databrokerpb.TransactionRequest_Query{
				Query: &databrokerpb.QueryRequest{Type: recordType(), Limit: 10},
			},
		})
		res, err = stream.Recv()
		require.NoError(t, err)
		assert.NotNil(t, res.GetOperation().GetQuery())

		sendCommit(t, stream)
		commit, err := recvCommit(t, stream)
		require.NoError(t, err)
		assert.False(t, commit.GetShared())

		assertRecordExists(t, srv, "op-1")
	})

	t.Run("rollback on half-close", func(t *testing.T) {
		srv := newServer(t)
		client := newTransactionClient(t, srv)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "half-close").GetBegin())
		sendOperation(t, stream, 1, putOperation(newTransactionRecord("half-close-1")))
		_, err = stream.Recv()
		require.NoError(t, err)
		require.NoError(t, stream.CloseSend())

		_, err = recvCommit(t, stream)
		assert.Error(t, err)
		assert.NotErrorIs(t, err, io.EOF)

		assertRecordMissing(t, srv, "half-close-1")
	})

	t.Run("rollback on cancel", func(t *testing.T) {
		srv := newServer(t)
		client := newTransactionClient(t, srv)

		ctx, cancel := context.WithCancel(t.Context())
		stream, err := client.Transaction(ctx)
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "cancel").GetBegin())
		sendOperation(t, stream, 1, putOperation(newTransactionRecord("cancel-1")))
		_, err = stream.Recv()
		require.NoError(t, err)
		cancel()

		_, err = recvCommit(t, stream)
		assert.Equal(t, codes.Canceled, status.Code(err))

		assertRecordMissing(t, srv, "cancel-1")
	})

	t.Run("first message must be begin", func(t *testing.T) {
		srv := newServer(t)
		client := newTransactionClient(t, srv)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		sendOperation(t, stream, 1, putOperation(newTransactionRecord("no-begin-1")))

		_, err = recvCommit(t, stream)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))

		assertRecordMissing(t, srv, "no-begin-1")
	})

	t.Run("second begin is rejected", func(t *testing.T) {
		srv := newServer(t)
		client := newTransactionClient(t, srv)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "double-begin").GetBegin())
		sendOperation(t, stream, 1, putOperation(newTransactionRecord("double-begin-1")))
		_, err = stream.Recv()
		require.NoError(t, err)
		sendBegin(t, stream, "double-begin")

		_, err = recvCommit(t, stream)
		assert.Equal(t, codes.InvalidArgument, status.Code(err))

		assertRecordMissing(t, srv, "double-begin-1")
	})

	t.Run("atomic", func(t *testing.T) {
		srv := newServer(t)
		client := newTransactionClient(t, srv)

		// hold the key from the test side so the stream below is certainly suppressed
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
			})
			holder <- err
		}()
		<-held

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)
		sendBegin(t, stream, "shared-key")
		sendOperation(t, stream, 1, putOperation(newTransactionRecord("suppressed")))

		responses := make(chan *databrokerpb.TransactionStreamResponse, 1)
		go func() {
			res, err := stream.Recv()
			if err == nil {
				responses <- res
			}
			close(responses)
		}()

		// while the key is held the stream is parked in singleflight, unacked
		require.Never(t, func() bool {
			select {
			case <-responses:
				return true
			default:
				return false
			}
		}, 500*time.Millisecond, 25*time.Millisecond)

		close(release)
		require.NoError(t, <-holder)

		res, ok := <-responses
		require.True(t, ok)
		require.Nil(t, res.GetBegin(), "suppressed transaction should not be acked")
		assert.True(t, res.GetCommit().GetShared())

		assertRecordExists(t, srv, "holder")
		assertRecordMissing(t, srv, "suppressed")

		// suppression is concurrent-only: a later transaction on the same key runs
		next, err := client.Transaction(t.Context())
		require.NoError(t, err)
		require.NotNil(t, beginTransaction(t, next, "shared-key").GetBegin())
		sendOperation(t, next, 1, getOperation("holder"))
		res, err = next.Recv()
		require.NoError(t, err)
		assert.Equal(t, "holder", res.GetOperation().GetGet().GetRecord().GetId())

		sendOperation(t, next, 2, putOperation(newTransactionRecord("next")))
		_, err = next.Recv()
		require.NoError(t, err)
		sendCommit(t, next)

		nextCommit, err := recvCommit(t, next)
		require.NoError(t, err)
		assert.False(t, nextCommit.GetShared())
		assertRecordExists(t, srv, "next")
	})

	t.Run("max duration", func(t *testing.T) {
		originalMaxDuration := transactionMaxDuration
		transactionMaxDuration = 100 * time.Millisecond
		t.Cleanup(func() { transactionMaxDuration = originalMaxDuration })

		srv := newServer(t)
		client := newTransactionClient(t, srv)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "max-duration").GetBegin())
		sendOperation(t, stream, 1, putOperation(newTransactionRecord("max-duration-1")))
		_, err = stream.Recv()
		require.NoError(t, err)

		_, err = recvCommit(t, stream)
		assert.Equal(t, codes.DeadlineExceeded, status.Code(err))

		assertRecordMissing(t, srv, "max-duration-1")
	})

	t.Run("sequence echoes", func(t *testing.T) {
		srv := newServer(t)
		client := newTransactionClient(t, srv)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)

		require.NotNil(t, beginTransaction(t, stream, "sequence").GetBegin())

		sequences := []uint64{7, 3, 9}
		for i, sequence := range sequences {
			sendOperation(t, stream, sequence, putOperation(newTransactionRecord(string(rune('a'+i)))))
		}
		for _, sequence := range sequences {
			res, err := stream.Recv()
			require.NoError(t, err)
			assert.Equal(t, sequence, res.GetSequence())
		}

		sendCommit(t, stream)
		_, err = recvCommit(t, stream)
		require.NoError(t, err)
	})

	t.Run("secured", func(t *testing.T) {
		underlying := newServer(t)
		secured := NewSecuredServer(underlying)
		sharedKey := cryptutil.NewKey()
		secured.OnConfigChange(t.Context(), config.New(&config.Options{
			SharedKey: base64.StdEncoding.EncodeToString(sharedKey),
		}))
		client := newTransactionClient(t, secured)

		stream, err := client.Transaction(t.Context())
		require.NoError(t, err)
		sendBegin(t, stream, "secured")
		_, err = recvCommit(t, stream)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))

		ctx, err := grpcutil.WithSignedJWT(t.Context(), sharedKey)
		require.NoError(t, err)
		commit := putInTransaction(ctx, t, client, "secured", newTransactionRecord("secured-1"))
		assert.False(t, commit.GetShared())
		assertRecordExists(t, underlying, "secured-1")
	})

	t.Run("follower forwards to leader", func(t *testing.T) {
		leader := newServer(t)
		leaderCC := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, leader)
		})
		local := newServer(t)
		follower := NewClusteredFollowerServer(noop.NewTracerProvider(), local, leaderCC)
		t.Cleanup(follower.Stop)
		client := newTransactionClient(t, follower)

		commit := putInTransaction(t.Context(), t, client, "follower", newTransactionRecord("follower-1"))
		assert.False(t, commit.GetShared())
		assertRecordExists(t, leader, "follower-1")
		assertRecordMissing(t, local, "follower-1")

		// a client that breaks mid-transaction rolls back on the leader
		ctx, cancel := context.WithCancel(t.Context())
		stream, err := client.Transaction(ctx)
		require.NoError(t, err)
		require.NotNil(t, beginTransaction(t, stream, "follower").GetBegin())
		sendOperation(t, stream, 1, putOperation(newTransactionRecord("follower-2")))
		_, err = stream.Recv()
		require.NoError(t, err)
		cancel()

		_, err = recvCommit(t, stream)
		assert.Error(t, err)
		assertRecordMissing(t, leader, "follower-2")
	})
}
