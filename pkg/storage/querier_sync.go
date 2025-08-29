package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	grpc "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type syncQuerier struct {
	client     databroker.DataBrokerServiceClient
	recordType string

	cancel context.CancelFunc

	mu                   sync.RWMutex
	ready                bool
	records              RecordCollection
	serverVersion        uint64
	minimumRecordVersion uint64
	latestRecordVersion  uint64
}

// NewSyncQuerier creates a new Querier backed by an in-memory record collection
// filled via sync calls to the databroker.
func NewSyncQuerier(
	client databroker.DataBrokerServiceClient,
	recordType string,
) Querier {
	q := &syncQuerier{
		client:     client,
		recordType: recordType,
		records:    NewRecordCollection(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	q.cancel = cancel
	go q.run(ctx)

	return q
}

func (q *syncQuerier) InvalidateCache(_ context.Context, req *databroker.QueryRequest) {
	v := req.MinimumRecordVersionHint
	if v == nil {
		return
	}

	q.mu.Lock()
	q.minimumRecordVersion = max(q.minimumRecordVersion, *v)
	q.mu.Unlock()
}

func (q *syncQuerier) Query(_ context.Context, req *databroker.QueryRequest, _ ...grpc.CallOption) (*databroker.QueryResponse, error) {
	q.mu.RLock()
	if !q.canHandleQueryLocked(req) {
		q.mu.RUnlock()
		return nil, ErrUnavailable
	}
	defer q.mu.RUnlock()
	return QueryRecordCollections(map[string]RecordCollection{
		q.recordType: q.records,
	}, req)
}

func (q *syncQuerier) Stop() {
	q.cancel()
}

func (q *syncQuerier) canHandleQueryLocked(req *databroker.QueryRequest) bool {
	if !q.ready {
		return false
	}
	if req.GetType() != q.recordType {
		return false
	}
	// if the latest record version hasn't reached the minimum version our sync is out-of-date
	// so we can't handle queries
	if q.latestRecordVersion < q.minimumRecordVersion {
		return false
	}
	if req.MinimumRecordVersionHint != nil && q.latestRecordVersion < *req.MinimumRecordVersionHint {
		return false
	}
	return true
}

func (q *syncQuerier) run(ctx context.Context) {
	bo := backoff.WithContext(backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0)), ctx)
	_ = backoff.RetryNotify(func() error {
		if q.serverVersion == 0 {
			err := q.syncLatest(ctx)
			if err != nil {
				if status.Code(err) == codes.Canceled {
					return backoff.Permanent(err)
				}
				return err
			}
		}

		err := q.sync(ctx)
		if status.Code(err) == codes.Canceled {
			return backoff.Permanent(err)
		}
		return err
	}, bo, func(err error, d time.Duration) {
		log.Ctx(ctx).Error().
			Err(err).
			Dur("delay", d).
			Msg("storage/sync-querier: error syncing records")
	})
}

func (q *syncQuerier) syncLatest(ctx context.Context) error {
	stream, err := q.client.SyncLatest(ctx, &databroker.SyncLatestRequest{
		Type: q.recordType,
	})
	if err != nil {
		return fmt.Errorf("error starting sync latest stream: %w", err)
	}

	q.mu.Lock()
	q.ready = false
	q.records.Clear()
	q.mu.Unlock()

	for {
		res, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return fmt.Errorf("error receiving sync latest message: %w", err)
		}

		switch res := res.Response.(type) {
		case *databroker.SyncLatestResponse_Record:
			q.mu.Lock()
			q.records.Put(res.Record)
			q.mu.Unlock()
		case *databroker.SyncLatestResponse_Versions:
			q.mu.Lock()
			q.serverVersion = res.Versions.ServerVersion
			q.latestRecordVersion = res.Versions.LatestRecordVersion
			q.mu.Unlock()
		default:
			return fmt.Errorf("unknown message type from sync latest: %T", res)
		}
	}

	q.mu.Lock()
	log.Ctx(ctx).Info().
		Str("record-type", q.recordType).
		Int("record-count", q.records.Len()).
		Uint64("latest-record-version", q.latestRecordVersion).
		Msg("storage/sync-querier: synced latest records")
	q.ready = true
	q.mu.Unlock()

	return nil
}

func (q *syncQuerier) sync(ctx context.Context) error {
	q.mu.RLock()
	req := &databroker.SyncRequest{
		ServerVersion: q.serverVersion,
		RecordVersion: q.latestRecordVersion,
		Type:          q.recordType,
	}
	q.mu.RUnlock()

	stream, err := q.client.Sync(ctx, req)
	if err != nil {
		return fmt.Errorf("error starting sync stream: %w", err)
	}

	for {
		res, err := stream.Recv()
		if errors.Is(err, databroker.ErrInvalidRecordVersion) || errors.Is(err, databroker.ErrInvalidServerVersion) {
			// this indicates the server version changed, so we need to reset
			q.mu.Lock()
			q.serverVersion = 0
			q.latestRecordVersion = 0
			q.minimumRecordVersion = 0
			q.mu.Unlock()
			return fmt.Errorf("stream was aborted due to mismatched versions: %w", err)
		} else if err != nil {
			return fmt.Errorf("error receiving sync message: %w", err)
		}

		q.mu.Lock()
		q.latestRecordVersion = max(q.latestRecordVersion, res.Record.Version)
		q.records.Put(res.Record)
		q.mu.Unlock()
	}
}
