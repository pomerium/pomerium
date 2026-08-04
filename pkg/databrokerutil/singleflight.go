package databrokerutil

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

var ErrTransactionClosed = errors.New("databrokerutil: transaction is closed")

// Transaction is not safe for concurrent use: the underlying stream is a strict
// request/response ping-pong.
type Transaction func(
	*databroker.TransactionRequest,
) (*databroker.TransactionResponse, error)

// Do runs work inside a databroker transaction keyed by key.
//
// If work returns nil the transaction is committed; if it returns an error the
// transaction is rolled back and that error is returned.
//
// Transactions are singleflight by key: if another transaction for the same key
// is already in flight, work is not called and Do reports shared=true after the
// in-flight transaction finishes.
func Do(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	key string,
	work func(Transaction) error,
) (shared bool, err error) {
	// rollback is expressed by ending the stream without a commit, so cancelling
	// on every exit path both rolls back and unblocks the server handler. A
	// deliberate rollback therefore shows up as a cancelled RPC server-side.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := client.Transaction(ctx)
	if err != nil {
		return false, err
	}

	var seq uint64
	next := func() uint64 {
		seq++
		return seq
	}

	err = stream.Send(&databroker.TransactionStreamRequest{
		Sequence: next(),
		Message: &databroker.TransactionStreamRequest_Begin{
			Begin: &databroker.BeginTransaction{Key: key},
		},
	})
	if err != nil {
		return false, err
	}

	res, err := stream.Recv()
	if err != nil {
		return false, err
	}
	// a suppressed transaction is never acked: the first and only message is the commit
	if commit := res.GetCommit(); commit != nil {
		return commit.GetShared(), nil
	}
	if res.GetBegin() == nil {
		return false, fmt.Errorf("databrokerutil: expected a begin response, got %T", res.GetMessage())
	}

	var mu sync.Mutex
	var done bool
	var submitErr error // the first transport error should be treated as the transaction failing
	tx := func(op *databroker.TransactionRequest) (*databroker.TransactionResponse, error) {
		mu.Lock()
		defer mu.Unlock()

		if done {
			return nil, ErrTransactionClosed
		}
		if submitErr != nil {
			return nil, submitErr
		}

		err := stream.Send(&databroker.TransactionStreamRequest{
			Sequence: next(),
			Message:  &databroker.TransactionStreamRequest_Operation{Operation: op},
		})
		if err != nil {
			submitErr = err
			return nil, err
		}

		res, err := stream.Recv()
		if err != nil {
			submitErr = err
			return nil, err
		}
		if res.GetOperation() == nil {
			submitErr = fmt.Errorf("databrokerutil: expected an operation response, got %T", res.GetMessage())
			return nil, submitErr
		}
		return res.GetOperation(), nil
	}
	defer func() {
		mu.Lock()
		done = true
		mu.Unlock()
	}()

	if err := work(tx); err != nil {
		// the stream error after a rollback is always context.Canceled and carries
		// no information, so the caller's error is what's worth returning
		return false, err
	}
	if submitErr != nil {
		return false, submitErr
	}

	err = stream.Send(&databroker.TransactionStreamRequest{
		Sequence: next(),
		Message:  &databroker.TransactionStreamRequest_Commit{Commit: new(databroker.CommitTransaction)},
	})
	if err != nil {
		return false, err
	}

	res, err = stream.Recv()
	if err != nil {
		return false, err
	}
	if res.GetCommit() == nil {
		return false, fmt.Errorf("databrokerutil: expected a commit response, got %T", res.GetMessage())
	}
	return res.GetCommit().GetShared(), nil
}

// Get submits a get operation.
func (tx Transaction) Get(recordType, id string) (*databroker.GetResponse, error) {
	res, err := tx(&databroker.TransactionRequest{
		Operation: &databroker.TransactionRequest_Get{
			Get: &databroker.GetRequest{Type: recordType, Id: id},
		},
	})
	if err != nil {
		return nil, err
	}
	if res.GetGet() == nil {
		return nil, fmt.Errorf("databrokerutil: expected a get response, got %T", res.GetOperation())
	}
	return res.GetGet(), nil
}

// Put submits a put operation.
func (tx Transaction) Put(records ...*databroker.Record) (*databroker.PutResponse, error) {
	res, err := tx(&databroker.TransactionRequest{
		Operation: &databroker.TransactionRequest_Put{
			Put: &databroker.PutRequest{Records: records},
		},
	})
	if err != nil {
		return nil, err
	}
	if res.GetPut() == nil {
		return nil, fmt.Errorf("databrokerutil: expected a put response, got %T", res.GetOperation())
	}
	return res.GetPut(), nil
}

// Patch submits a patch operation.
func (tx Transaction) Patch(mask *fieldmaskpb.FieldMask, records ...*databroker.Record) (*databroker.PatchResponse, error) {
	res, err := tx(&databroker.TransactionRequest{
		Operation: &databroker.TransactionRequest_Patch{
			Patch: &databroker.PatchRequest{FieldMask: mask, Records: records},
		},
	})
	if err != nil {
		return nil, err
	}
	if res.GetPatch() == nil {
		return nil, fmt.Errorf("databrokerutil: expected a patch response, got %T", res.GetOperation())
	}
	return res.GetPatch(), nil
}

// Query submits a query operation.
func (tx Transaction) Query(req *databroker.QueryRequest) (*databroker.QueryResponse, error) {
	res, err := tx(&databroker.TransactionRequest{
		Operation: &databroker.TransactionRequest_Query{Query: req},
	})
	if err != nil {
		return nil, err
	}
	if res.GetQuery() == nil {
		return nil, fmt.Errorf("databrokerutil: expected a query response, got %T", res.GetOperation())
	}
	return res.GetQuery(), nil
}
