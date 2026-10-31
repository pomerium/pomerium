package mcp

import (
	"context"
	"fmt"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

const (
	defaultRefreshTokenCleanupInterval    = 5 * time.Minute
	defaultRefreshTokenCleanupGracePeriod = time.Minute * 15
)

type RefreshTokenMd struct {
	Revoked   bool
	RevokedAt time.Time
	ExpiresAt time.Time
}

type StorageSyncer struct {
	clientB databroker.ClientGetter
	records map[string]*RefreshTokenMd
	StorageSyncerOptions

	mu sync.RWMutex
}

type StorageSyncerOptions struct {
	// how often to cleanup refresh tokens
	cleanupInterval time.Duration
	// the grace period after which to clean up a token once it has been revoked
	cleanupGracePeriodDuration time.Duration
	// allows for fake clock tests
	now func() time.Time
}

func defaultStorageSyncerOptions() *StorageSyncerOptions {
	return &StorageSyncerOptions{
		cleanupInterval:            defaultRefreshTokenCleanupInterval,
		cleanupGracePeriodDuration: defaultRefreshTokenCleanupGracePeriod,
		now:                        time.Now,
	}
}

func (o *StorageSyncerOptions) Apply(opts ...StorageSyncerOption) {
	for _, opt := range opts {
		opt(o)
	}
}

type StorageSyncerOption func(*StorageSyncerOptions)

func WithCleanupInterval(d time.Duration) StorageSyncerOption {
	return func(o *StorageSyncerOptions) { o.cleanupInterval = d }
}

func WithCleanupGracePeriod(d time.Duration) StorageSyncerOption {
	return func(o *StorageSyncerOptions) { o.cleanupGracePeriodDuration = d }
}

func WithClock(now func() time.Time) StorageSyncerOption {
	return func(o *StorageSyncerOptions) { o.now = now }
}

func NewStorageSyncer(
	clientB databroker.ClientGetter,
	opts ...StorageSyncerOption,
) *StorageSyncer {
	options := defaultStorageSyncerOptions()
	options.Apply(opts...)

	return &StorageSyncer{
		clientB:              clientB,
		records:              map[string]*RefreshTokenMd{},
		StorageSyncerOptions: *options,
	}
}

var _ databrokerutil.SyncerHandler = (*StorageSyncer)(nil)

func (s *StorageSyncer) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return databrokerutil.NewSyncer(
			ctx,
			"mcp-storage-syncer",
			s,
			databrokerutil.WithTypeURL("type.googleapis.com/oauth21.MCPRefreshToken"),
			databrokerutil.WithFastForward(),
		).Run(ctx)
	})
	eg.Go(func() error {
		return s.RunCleanUp(ctx)
	})

	return eg.Wait()
}

func (s *StorageSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return s.clientB.GetDataBrokerServiceClient()
}

func (s *StorageSyncer) ClearRecords(_ context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = map[string]*RefreshTokenMd{}
}

func (s *StorageSyncer) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	for _, rec := range records {
		id := rec.GetId()
		if rec.GetDeletedAt() != nil {
			delete(s.records, id)
			continue
		}

		refreshTokenProto := new(oauth21.MCPRefreshToken)
		if err := rec.GetData().UnmarshalTo(refreshTokenProto); err != nil {
			log.Ctx(ctx).Error().Err(err).
				Str("record-id", id).
				Msg("mcp: failed to unmarshal refresh token record")
			continue
		}

		expiresAt := refreshTokenProto.GetExpiresAt().AsTime()

		got, ok := s.records[id]
		if !ok {
			md := &RefreshTokenMd{
				Revoked:   refreshTokenProto.GetRevoked(),
				ExpiresAt: expiresAt,
			}
			if md.Revoked {
				md.RevokedAt = now
			}
			s.records[id] = md
			continue
		}
		// explicitly only handle flips from false -> true
		if !got.Revoked && refreshTokenProto.GetRevoked() {
			got.Revoked = true
			got.RevokedAt = now
		}
		got.ExpiresAt = expiresAt
	}
}

// RunCleanUp periodically deletes revoked and expired refresh tokens until ctx is done.
func (s *StorageSyncer) RunCleanUp(ctx context.Context) error {
	t := time.NewTicker(s.cleanupInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-t.C:
			if err := s.batchCleanUp(ctx); err != nil {
				log.Ctx(ctx).Error().Err(err).Msg("mcp: failed to clean up refresh tokens")
			}
		}
	}
}

// expired reports whether the record is eligible for deletion.
func (s *StorageSyncer) expired(md *RefreshTokenMd, now time.Time) bool {
	if md.Revoked && md.RevokedAt.Add(s.cleanupGracePeriodDuration).Before(now) {
		return true
	}

	return md.ExpiresAt.Add(s.cleanupGracePeriodDuration).Before(now)
}

func (s *StorageSyncer) batchCleanUp(ctx context.Context) error {
	now := s.now()

	s.mu.RLock()
	var ids []string
	for id, md := range s.records {
		if s.expired(md, now) {
			ids = append(ids, id)
		}
	}
	s.mu.RUnlock()

	if len(ids) == 0 {
		return nil
	}

	data := protoutil.NewAny(new(oauth21.MCPRefreshToken))
	deletedAt := timestamppb.New(now)
	recs := make([]*databroker.Record, 0, len(ids))
	for _, id := range ids {
		recs = append(recs, &databroker.Record{
			Id:        id,
			Data:      data,
			Type:      data.TypeUrl,
			DeletedAt: deletedAt,
		})
	}

	if _, err := s.GetDataBrokerServiceClient().Put(ctx, &databroker.PutRequest{Records: recs}); err != nil {
		return fmt.Errorf("failed to delete expired mcp refresh tokens: %w", err)
	}

	log.Ctx(ctx).Info().
		Int("count", len(ids)).
		Msg("mcp: deleted expired refresh tokens")
	return nil
}
