package databrokerutil

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var (
	ErrTransactionClosed  = errors.New("databrokerutil: transaction is closed")
	ErrTransactionAborted = func(err error) error {
		return status.Error(codes.Aborted, fmt.Sprintf("databrokerutil: transaction stream closed before commit : %s", err))
	}
)

type transactionClient = grpc.BidiStreamingClient[databroker.TransactionStreamRequest, databroker.TransactionStreamResponse]

// TX submits storage operations during a singleflight operation to the databroker.
// It is safe for concurrent use, but operations are submitted sequentially to the underlying transaction.
// When used concurrently, there is no guarantee on operation ordering.
type TX interface {
	Get(ctx context.Context, req *databroker.GetRequest) (resp *databroker.GetResponse, err error)
	Put(ctx context.Context, req *databroker.PutRequest) (resp *databroker.PutResponse, err error)
	Patch(ctx context.Context, req *databroker.PatchRequest) (resp *databroker.PatchResponse, err error)
	Query(ctx context.Context, req *databroker.QueryRequest) (resp *databroker.QueryResponse, err error)
}

type Transaction struct {
	key    string
	client transactionClient

	operation *storageOperatorStream
}

func NewTransaction(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
) (*Transaction, error) {
	stream, err := client.Transaction(ctx)
	if err != nil {
		return nil, err
	}
	seq := uint64(1)
	key := uuid.New().String()
	if _, err := initiateHandshake(
		stream,
		seq,
		key,
		databroker.TransactionType_TRANSACTION_TYPE_NOLOCK,
	); err != nil {
		if _, ok := status.FromError(err); !ok {
			return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("databrokerutil: failed to initiate transaction handshake : %s", err))
		}
		return nil, err
	}

	return &Transaction{
		client: stream,
		operation: &storageOperatorStream{
			key:         key,
			stream:      stream,
			sequenceNum: seq + 1,
		},
	}, nil
}

func (t *Transaction) TX() TX {
	return t.operation
}

func (t *Transaction) Commit() ([]*databroker.Record, error) {
	commitSeq := t.operation.Close()
	err := t.client.Send(&databroker.TransactionStreamRequest{
		Sequence: commitSeq,
		Message: &databroker.TransactionStreamRequest_Commit{
			Commit: new(databroker.CommitTransaction),
		},
	})
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, ErrTransactionAborted(err)
		}
		return nil, err
	}
	res, err := t.client.Recv()
	if err != nil {
		return nil, err
	}
	if res.GetCommit() == nil {
		return nil, status.Error(codes.FailedPrecondition, fmt.Sprintf("databrokerutil: expected a commit response, got %T", res.GetMessage()))
	}
	return res.GetCommit().GetRecords(), nil
}

// DoSingleFlight runs a distributed singleflight callback on storage operations inside the databroker.
// Returning an error inside the callback rollsback all submitted storage operations.
// Storage operations are only persisted on success.
// Error handling:
//   - `FailedPrecondition`: protocol errors, should not be retried.
//   - `Aborted`: connectivity errors to the databroker during the singleflight, can be retried.
//   - `DeadlineExceeded` : transaction exceeded the alloted time set by the server, can be retried.
//   - `Internal`: storage errors related to locking mechanisms, persistence and other internal
//     failures that can cause the singleflight to fail.
func DoSingleFlight(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	key string,
	work func(TX) error,
) (changed []*databroker.Record, shared bool, err error) {
	// rollback is expressed by ending the stream without a commit, so cancelling
	// on every exit path both rolls back and unblocks the server handler
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := client.Transaction(ctx)
	if err != nil {
		return nil, false, err
	}

	seq := uint64(1)
	res, err := initiateHandshake(stream, seq, key, databroker.TransactionType_TRANSACTION_TYPE_SINGLEFLIGHT)
	if err != nil {
		if _, ok := status.FromError(err); !ok {
			return nil, false, status.Error(codes.FailedPrecondition, fmt.Sprintf("databrokerutil: failed to initiate singleflight handshake : %s", err))
		}
		return nil, false, err
	}
	// a shared transaction is never acked: the first and only message is the commit
	if commit := res.GetCommit(); commit != nil {
		return res.GetCommit().GetRecords(), commit.GetShared(), nil
	}
	if res.GetBegin() == nil {
		return nil, false, status.Error(codes.FailedPrecondition, fmt.Sprintf("databrokerutil: expected a begin response, got %T", res.GetMessage()))
	}

	op := &storageOperatorStream{
		sequenceNum: seq + 1,
		key:         key,
		stream:      stream,
	}

	if err := work(op); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, false, ErrTransactionAborted(err)
		}
		return nil, false, err
	}

	commitSeq := op.Close()
	err = stream.Send(&databroker.TransactionStreamRequest{
		Sequence: commitSeq,
		Message: &databroker.TransactionStreamRequest_Commit{
			Commit: &databroker.CommitTransaction{
				Key: key,
			},
		},
	})
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, false, ErrTransactionAborted(err)
		}
		return nil, false, err
	}
	res, err = stream.Recv()
	if err != nil {
		return nil, false, err
	}
	if res.GetCommit() == nil {
		return nil, false, status.Error(codes.FailedPrecondition, fmt.Sprintf("databrokerutil: expected a commit response, got %T", res.GetMessage()))
	}
	return res.GetCommit().GetRecords(), res.GetCommit().GetShared(), nil
}

func initiateHandshake(
	stream transactionClient,
	sequence uint64,
	key string,
	transactionType databroker.TransactionType,
) (*databroker.TransactionStreamResponse, error) {
	if err := stream.Send(&databroker.TransactionStreamRequest{
		Sequence: sequence,
		Message: &databroker.TransactionStreamRequest_Begin{
			Begin: &databroker.BeginTransaction{
				Key:  key,
				Type: transactionType,
			},
		},
	}); err != nil {
		return nil, err
	}

	res, err := stream.Recv()
	return res, err
}

// func example(
// 	ctx context.Context,
// 	client databroker.DataBrokerServiceClient,
// ) {
// 	conn, err := databrokerutil.NewTransaction(ctx, client)
// 	if err != nil {
// 		panic(err)
// 	}
// 	tx := conn.TX()
// 	tx.Get(ctx, &databroker.GetRequest{})
// 	tx.Put(ctx, &databroker.PutRequest{})
// 	tx.Patch(ctx, &databroker.PatchRequest{})
// 	tx.Query(ctx, &databroker.QueryRequest{})

// 	changed, err := conn.Commit()
// 	if err != nil {
// 		panic(err)
// 	}
// 	fmt.Println(changed)
// }

// assumes the begin handshake succeeded and we "own" the transaction.
type storageOperatorStream struct {
	key    string
	stream transactionClient

	sequenceNum uint64
	mu          sync.Mutex
	done        bool
}

func (s *storageOperatorStream) getSequenceNumLocked() uint64 {
	s.sequenceNum++
	return s.sequenceNum
}

func (s *storageOperatorStream) Get(_ context.Context, req *databroker.GetRequest) (*databroker.GetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.isClosedLocked(); err != nil {
		return nil, err
	}
	sequence := s.getSequenceNumLocked()
	sendReq := &databroker.TransactionStreamRequest{
		Sequence: sequence,
		Message: &databroker.TransactionStreamRequest_Operation{
			Operation: &databroker.TransactionRequest{
				Key: s.key,
				Operation: &databroker.TransactionRequest_Get{
					Get: req,
				},
			},
		},
	}
	if err := s.stream.Send(sendReq); err != nil {
		return nil, err
	}

	resp, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	if err := s.validateResponse(sendReq, resp, sequence); err != nil {
		return nil, err
	}

	if rpcErr := resp.GetOperation().Err; rpcErr != nil {
		return nil, status.Error(codes.Code(rpcErr.GetCode()), rpcErr.GetMessage())
	}

	return resp.GetOperation().GetResponse().GetGet(), nil
}

func (s *storageOperatorStream) Put(_ context.Context, req *databroker.PutRequest) (*databroker.PutResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.isClosedLocked(); err != nil {
		return nil, err
	}
	sequence := s.getSequenceNumLocked()
	sendReq := &databroker.TransactionStreamRequest{
		Sequence: sequence,
		Message: &databroker.TransactionStreamRequest_Operation{
			Operation: &databroker.TransactionRequest{
				Key: s.key,
				Operation: &databroker.TransactionRequest_Put{
					Put: req,
				},
			},
		},
	}
	if err := s.stream.Send(sendReq); err != nil {
		return nil, err
	}

	resp, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	if err := s.validateResponse(sendReq, resp, sequence); err != nil {
		return nil, err
	}

	if rpcErr := resp.GetOperation().Err; rpcErr != nil {
		return nil, status.Error(codes.Code(rpcErr.GetCode()), rpcErr.GetMessage())
	}

	return resp.GetOperation().GetResponse().GetPut(), nil
}

func (s *storageOperatorStream) Patch(_ context.Context, req *databroker.PatchRequest) (*databroker.PatchResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.isClosedLocked(); err != nil {
		return nil, err
	}
	sequence := s.getSequenceNumLocked()
	sendReq := &databroker.TransactionStreamRequest{
		Sequence: sequence,
		Message: &databroker.TransactionStreamRequest_Operation{
			Operation: &databroker.TransactionRequest{
				Key: s.key,
				Operation: &databroker.TransactionRequest_Patch{
					Patch: req,
				},
			},
		},
	}
	if err := s.stream.Send(sendReq); err != nil {
		return nil, err
	}

	resp, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	if err := s.validateResponse(sendReq, resp, sequence); err != nil {
		return nil, err
	}

	if rpcErr := resp.GetOperation().Err; rpcErr != nil {
		return nil, status.Error(codes.Code(rpcErr.GetCode()), rpcErr.GetMessage())
	}

	return resp.GetOperation().GetResponse().GetPatch(), nil
}

func (s *storageOperatorStream) Query(_ context.Context, req *databroker.QueryRequest) (*databroker.QueryResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.isClosedLocked(); err != nil {
		return nil, err
	}
	sequence := s.getSequenceNumLocked()
	sendReq := &databroker.TransactionStreamRequest{
		Sequence: sequence,
		Message: &databroker.TransactionStreamRequest_Operation{
			Operation: &databroker.TransactionRequest{
				Key: s.key,
				Operation: &databroker.TransactionRequest_Query{
					Query: req,
				},
			},
		},
	}
	if err := s.stream.Send(sendReq); err != nil {
		return nil, err
	}

	resp, err := s.stream.Recv()
	if err != nil {
		return nil, err
	}
	if err := s.validateResponse(sendReq, resp, sequence); err != nil {
		return nil, err
	}

	if rpcErr := resp.GetOperation().Err; rpcErr != nil {
		return nil, status.Error(codes.Code(rpcErr.GetCode()), rpcErr.GetMessage())
	}

	return resp.GetOperation().GetResponse().GetQuery(), nil
}

func (s *storageOperatorStream) isClosedLocked() error {
	if s.done {
		return status.Error(codes.FailedPrecondition, "calling storage operations on a transaction that has been marked done")
	}
	return nil
}

func (s *storageOperatorStream) Close() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	return s.sequenceNum
}

func (s *storageOperatorStream) validateResponse(
	req *databroker.TransactionStreamRequest,
	resp *databroker.TransactionStreamResponse,
	sequence uint64,
) error {
	if resp.GetOperation() == nil {
		return status.Error(codes.FailedPrecondition, "expected response to an operation from server")
	}
	if resp.GetSequence() != sequence {
		return status.Error(codes.FailedPrecondition, "unexpected sequence gap in Transaction protocol")
	}
	if resp.GetOperation().Err == nil {
		if err := checkOperationTypeMatch(req.GetOperation(), resp.GetOperation().GetResponse()); err != nil {
			return err
		}
	}
	return nil
}

func checkOperationTypeMatch(req *databroker.TransactionRequest, resp *databroker.TransactionResponse) error {
	var ok bool
	switch req.GetOperation().(type) {
	case *databroker.TransactionRequest_Get:
		ok = resp.GetGet() != nil
	case *databroker.TransactionRequest_Put:
		ok = resp.GetPut() != nil
	case *databroker.TransactionRequest_Patch:
		ok = resp.GetPatch() != nil
	case *databroker.TransactionRequest_Query:
		ok = resp.GetQuery() != nil
	}
	if !ok {
		return status.Errorf(
			codes.FailedPrecondition,
			"unexpected operation type in Transaction protocol: requested %T, got %T",
			req.GetOperation(), resp.GetOperation(),
		)
	}
	return nil
}
