package file

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/cockroachdb/pebble/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

type transaction struct {
	backend *Backend
	ctx     context.Context

	batch             *pebble.Batch
	onCommitCallbacks []func()
	responses         []*databrokerpb.TransactionResponse
	changed           []*databrokerpb.Record
}

func (tx *transaction) onCommit(callback func()) {
	tx.onCommitCallbacks = append(tx.onCommitCallbacks, callback)
}

// Submit applies a single operation to the transaction's batch. The operation is
// not durable until the transaction commits.
func (tx *transaction) Submit(req *databrokerpb.TransactionRequest) (*databrokerpb.TransactionResponse, error) {
	if tx.ctx.Err() != nil {
		return nil, context.Cause(tx.ctx)
	}

	tx.backend.mu.Lock()
	defer tx.backend.mu.Unlock()

	if err := tx.checkClosedLocked(); err != nil {
		return nil, err
	}

	var res *databrokerpb.TransactionResponse
	var err error
	switch op := req.GetOperation().(type) {
	case *databrokerpb.TransactionRequest_Get:
		res, err = tx.submitGetLocked(op.Get)
	case *databrokerpb.TransactionRequest_Put:
		res, err = tx.submitPutLocked(op.Put)
	case *databrokerpb.TransactionRequest_Patch:
		res, err = tx.submitPatchLocked(op.Patch)
	case *databrokerpb.TransactionRequest_Query:
		res, err = tx.submitQueryLocked(op.Query)
	default:
		err = status.Errorf(codes.InvalidArgument, "unsupported transaction operation: %T", req.GetOperation())
	}
	if err != nil {
		return nil, err
	}

	res.Key = req.GetKey()
	tx.responses = append(tx.responses, res)
	return res, nil
}

func (tx *transaction) submitGetLocked(req *databrokerpb.GetRequest) (*databrokerpb.TransactionResponse, error) {
	record, err := tx.backend.getRecordLocked(tx.batch, req.GetType(), req.GetId())
	if err != nil {
		return nil, err
	}
	return &databrokerpb.TransactionResponse{
		Operation: &databrokerpb.TransactionResponse_Get{Get: &databrokerpb.GetResponse{Record: record}},
	}, nil
}

func (tx *transaction) submitPutLocked(req *databrokerpb.PutRequest) (*databrokerpb.TransactionResponse, error) {
	records := slices.Clone(req.GetRecords())
	serverVersion := tx.backend.serverVersion
	if err := tx.backend.putRecordsLocked(tx.batch, records); err != nil {
		return nil, err
	}
	tx.onCommit(func() { tx.backend.onRecordChange.Broadcast(tx.ctx) })
	tx.changed = append(tx.changed, records...)
	return &databrokerpb.TransactionResponse{
		Operation: &databrokerpb.TransactionResponse_Put{Put: &databrokerpb.PutResponse{
			ServerVersion: serverVersion,
			Records:       records,
		}},
	}, nil
}

func (tx *transaction) submitPatchLocked(req *databrokerpb.PatchRequest) (*databrokerpb.TransactionResponse, error) {
	serverVersion := tx.backend.serverVersion
	patched, err := tx.backend.patchRecordsLocked(tx.batch, req.GetRecords(), req.GetFieldMask())
	if err != nil {
		return nil, err
	}
	tx.onCommit(func() { tx.backend.onRecordChange.Broadcast(tx.ctx) })
	tx.changed = append(tx.changed, patched...)
	return &databrokerpb.TransactionResponse{
		Operation: &databrokerpb.TransactionResponse_Patch{Patch: &databrokerpb.PatchResponse{
			ServerVersion: serverVersion,
			Records:       patched,
		}},
	}, nil
}

func (tx *transaction) submitQueryLocked(req *databrokerpb.QueryRequest) (*databrokerpb.TransactionResponse, error) {
	expr, err := storage.FilterExpressionFromStruct(req.GetFilter())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid query filter: %v", err)
	}

	all, err := tx.backend.listLatestRecordsLocked(tx.batch, req.GetType(), expr)
	if err != nil {
		return nil, err
	}

	query := strings.ToLower(req.GetQuery())
	filtered := make([]*databrokerpb.Record, 0, len(all))
	for _, record := range all {
		if query != "" && !storage.MatchAny(record.GetData(), query) {
			continue
		}
		filtered = append(filtered, record)
	}

	records, totalCount := databrokerpb.ApplyOffsetAndLimit(filtered, int(req.GetOffset()), int(req.GetLimit()))
	return &databrokerpb.TransactionResponse{
		Operation: &databrokerpb.TransactionResponse_Query{Query: &databrokerpb.QueryResponse{
			Records:       records,
			TotalCount:    int64(totalCount),
			ServerVersion: tx.backend.serverVersion,
			RecordVersion: tx.backend.latestRecordVersion,
		}},
	}, nil
}

func (tx *transaction) checkClosedLocked() error {
	select {
	case <-tx.backend.closeCtx.Done():
		return context.Cause(tx.backend.closeCtx)
	default:
	}
	return nil
}

func (tx *transaction) rollback() {
	tx.backend.mu.Lock()
	defer tx.backend.mu.Unlock()
	if err := tx.checkClosedLocked(); err != nil {
		return
	}

	_ = tx.batch.Close()
}

// Commit writes the transaction's batch to the database. It deliberately does not
// check closeCtx: a transaction which has finished its callback runs to completion.
func (tx *transaction) Commit() error {
	tx.backend.mu.Lock()
	defer tx.backend.mu.Unlock()

	if err := tx.checkClosedLocked(); err != nil {
		return err
	}

	err := tx.batch.Commit(nil)
	_ = tx.batch.Close()
	if err != nil {
		return fmt.Errorf("pebble: error committing transaction: %w", err)
	}

	for _, f := range slices.Backward(tx.onCommitCallbacks) {
		f()
	}

	return nil
}
