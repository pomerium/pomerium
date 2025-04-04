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
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

type syncQuerier struct {
	client     databroker.DataBrokerServiceClient
	recordType string
	fallback   Querier

	cancel              context.CancelFunc
	serverVersion       uint64
	latestRecordVersion uint64

	mu      sync.RWMutex
	ready   bool
	records RecordCollection
}

// NewSyncQuerier creates a new Querier backed by an in-memory record collection
// filled via sync calls to the databroker.
func NewSyncQuerier(
	client databroker.DataBrokerServiceClient,
	recordType string,
	fallback Querier,
) Querier {
	q := &syncQuerier{
		client:     client,
		recordType: recordType,
		fallback:   fallback,
		records:    NewRecordCollection(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	q.cancel = cancel
	go q.run(ctx)

	return q
}

func (q *syncQuerier) InvalidateCache(
	ctx context.Context,
	req *databroker.QueryRequest,
) {
	q.mu.RLock()
	ready := q.ready
	q.mu.RUnlock()

	// only invalidate the fallback querier if we aren't ready yet
	if ready {
		q.fallback.InvalidateCache(ctx, req)
	}
}

func (q *syncQuerier) Query(
	ctx context.Context,
	req *databroker.QueryRequest,
	opts ...grpc.CallOption,
) (*databroker.QueryResponse, error) {
	q.mu.RLock()
	if !q.ready || req.GetType() != q.recordType {
		q.mu.RUnlock()
		return q.fallback.Query(ctx, req, opts...)
	}
	defer q.mu.RUnlock()
	return QueryRecordCollections(map[string]RecordCollection{
		q.recordType: q.records,
	}, req)
}

func (q *syncQuerier) Stop() {
	q.cancel()
}

func (q *syncQuerier) run(ctx context.Context) {
	bo := backoff.WithContext(backoff.NewExponentialBackOff(backoff.WithMaxElapsedTime(0)), ctx)
	_ = backoff.RetryNotify(func() error {
		if q.serverVersion == 0 {
			err := q.syncLatest(ctx)
			if err != nil {
				return err
			}
		}

		return q.sync(ctx)
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
			q.serverVersion = res.Versions.ServerVersion
			q.latestRecordVersion = res.Versions.LatestRecordVersion
		default:
			return fmt.Errorf("unknown message type from sync latest: %T", res)
		}
	}

	q.mu.Lock()
	q.ready = true
	q.mu.Unlock()

	return nil
}

func (q *syncQuerier) sync(ctx context.Context) error {
	stream, err := q.client.Sync(ctx, &databroker.SyncRequest{
		ServerVersion: q.serverVersion,
		RecordVersion: q.latestRecordVersion,
		Type:          q.recordType,
	})
	if err != nil {
		return fmt.Errorf("error starting sync stream: %w", err)
	}

	for {
		res, err := stream.Recv()
		if status.Code(err) == codes.Aborted {
			// this indicates the server version changed, so we need to reset
			q.serverVersion = 0
			q.latestRecordVersion = 0
			return fmt.Errorf("stream was aborted due to mismatched server versions: %w", err)
		} else if err != nil {
			return fmt.Errorf("error receiving sync message: %w", err)
		}

		q.latestRecordVersion = max(q.latestRecordVersion, res.Record.Version)

		q.mu.Lock()
		q.records.Put(res.Record)
		q.mu.Unlock()
	}
}
