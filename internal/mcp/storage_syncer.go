package mcp

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	oauth21 "github.com/pomerium/pomerium/internal/oauth21/gen"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/slices"
)

const (
	defaultRefreshTokenCleanupInterval    = 5 * time.Minute
	defaultRefreshTokenCleanupGracePeriod = time.Minute * 15
)

var ErrNoMCPToken = errors.New("session has no matching mcp token")

type RefreshTokenMd struct {
	Revoked   bool
	RevokedAt time.Time
	ExpiresAt time.Time
}

type StorageSyncerOptions struct {
	tokenOpts []TokenExpirationSyncerOption
}

func (o *StorageSyncerOptions) Apply(opts ...StorageSyncerOption) {
	for _, opt := range opts {
		opt(o)
	}
}

type StorageSyncerOption func(o *StorageSyncerOptions)

func WithTokenExpirationSyncerOption(opt TokenExpirationSyncerOption) StorageSyncerOption {
	return func(o *StorageSyncerOptions) {
		o.tokenOpts = append(o.tokenOpts, opt)
	}
}

type StorageSyncer struct {
	tokenExpiration    *tokenExpirationSyncer
	sessionTokenSyncer *sessionTokenSyncer
}

func NewStorageSyncer(
	clientB databroker.ClientGetter,
	opts ...StorageSyncerOption,
) *StorageSyncer {
	options := &StorageSyncerOptions{
		tokenOpts: []TokenExpirationSyncerOption{},
	}
	options.Apply(opts...)
	return &StorageSyncer{
		tokenExpiration:    newTokenExpirationSyncer(clientB, options.tokenOpts...),
		sessionTokenSyncer: newSessionTokenSyncer(clientB),
	}
}

func (s *StorageSyncer) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return s.tokenExpiration.Run(ctx)
	})
	eg.Go(func() error {
		return s.sessionTokenSyncer.Run(ctx)
	})

	return eg.Wait()
}

func newTokenExpirationSyncer(
	clientB databroker.ClientGetter,
	opts ...TokenExpirationSyncerOption,
) *tokenExpirationSyncer {
	options := defaultTokenExpirationSyncerOptions()
	options.Apply(opts...)
	return &tokenExpirationSyncer{
		clientB:                      clientB,
		records:                      map[string]*RefreshTokenMd{},
		mu:                           sync.RWMutex{},
		TokenExpirationSyncerOptions: *options,
	}
}

type tokenExpirationSyncer struct {
	clientB databroker.ClientGetter
	records map[string]*RefreshTokenMd
	TokenExpirationSyncerOptions

	mu sync.RWMutex
}

type TokenExpirationSyncerOptions struct {
	// how often to cleanup refresh tokens
	cleanupInterval time.Duration
	// the grace period after which to clean up a token once it has been revoked
	cleanupGracePeriodDuration time.Duration
	// allows for fake clock tests
	now func() time.Time
}

func defaultTokenExpirationSyncerOptions() *TokenExpirationSyncerOptions {
	return &TokenExpirationSyncerOptions{
		cleanupInterval:            defaultRefreshTokenCleanupInterval,
		cleanupGracePeriodDuration: defaultRefreshTokenCleanupGracePeriod,
		now:                        time.Now,
	}
}

func (o *TokenExpirationSyncerOptions) Apply(opts ...TokenExpirationSyncerOption) {
	for _, opt := range opts {
		opt(o)
	}
}

type TokenExpirationSyncerOption func(*TokenExpirationSyncerOptions)

func WithCleanupInterval(d time.Duration) TokenExpirationSyncerOption {
	return func(o *TokenExpirationSyncerOptions) { o.cleanupInterval = d }
}

func WithCleanupGracePeriod(d time.Duration) TokenExpirationSyncerOption {
	return func(o *TokenExpirationSyncerOptions) { o.cleanupGracePeriodDuration = d }
}

func WithClock(now func() time.Time) TokenExpirationSyncerOption {
	return func(o *TokenExpirationSyncerOptions) { o.now = now }
}

var _ databrokerutil.SyncerHandler = (*tokenExpirationSyncer)(nil)

func (s *tokenExpirationSyncer) Run(ctx context.Context) error {
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

func (s *tokenExpirationSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return s.clientB.GetDataBrokerServiceClient()
}

func (s *tokenExpirationSyncer) ClearRecords(_ context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = map[string]*RefreshTokenMd{}
}

func (s *tokenExpirationSyncer) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
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
func (s *tokenExpirationSyncer) RunCleanUp(ctx context.Context) error {
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
func (s *tokenExpirationSyncer) expired(md *RefreshTokenMd, now time.Time) bool {
	if md.Revoked && md.RevokedAt.Add(s.cleanupGracePeriodDuration).Before(now) {
		return true
	}

	return md.ExpiresAt.Add(s.cleanupGracePeriodDuration).Before(now)
}

func (s *tokenExpirationSyncer) batchCleanUp(ctx context.Context) error {
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

type sessionTokenSyncer struct {
	clientB databroker.ClientGetter
}

func newSessionTokenSyncer(clientB databroker.ClientGetter) *sessionTokenSyncer {
	return &sessionTokenSyncer{
		clientB: clientB,
	}
}

var _ databrokerutil.SyncerHandler = (*sessionTokenSyncer)(nil)

func (s *sessionTokenSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return s.clientB.GetDataBrokerServiceClient()
}
func (s *sessionTokenSyncer) ClearRecords(_ context.Context) {}

func (s *sessionTokenSyncer) queryMcpRefreshTokens(ctx context.Context, sessionID string) (*oauth21.MCPRefreshToken, error) {
	b := backoff.NewConstantBackOff(time.Second)
	mostRecent, err := backoff.RetryWithData(func() (*oauth21.MCPRefreshToken, error) {
		mcpRefreshTokens, err := s.clientB.GetDataBrokerServiceClient().
			Query(ctx, &databroker.QueryRequest{
				Type:   "type.googleapis.com/oauth21.MCPRefreshToken",
				Filter: indexedFieldFilter("initiating_session_id", sessionID),
				Limit:  50,
			})
		if err != nil {
			return nil, err
		}
		return mostRecentUsableRefreshToken(ctx, mcpRefreshTokens.GetRecords(), time.Now())
	}, backoff.WithMaxRetries(backoff.WithContext(b, ctx), 3))
	return mostRecent, err
}

func (s *sessionTokenSyncer) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
	for _, rec := range records {
		sessionID := rec.GetId()
		if rec.GetDeletedAt() != nil {
			continue
		}
		sessionProto := new(session.Session)
		if err := rec.GetData().UnmarshalTo(sessionProto); err != nil {
			log.Ctx(ctx).Error().Err(err).
				Str("record-id", sessionID).
				Msg("mcp: failed to unmarshal session record")
			continue
		}
		if sessionProto.GetOauthToken().GetRefreshToken() == "" {
			continue
		}
		mostRecent, err := s.queryMcpRefreshTokens(ctx, sessionID)
		if err != nil {
			if errors.Is(err, ErrNoMCPToken) {
				log.Ctx(ctx).Debug().Str("session-id", sessionID).Msg("mcp : session does not have a matching mcp refresh token")
			} else {
				log.Ctx(ctx).Err(err).Str("session-id", sessionID).Msg("mcp: failed to fetch matching mcp upstream records for session")
			}
		}
		if errors.Is(err, ErrNoMCPToken) {
			continue
		} else if err != nil {
			continue
		}
		// TODO : are there some cases here where this is undesirable?
		if mostRecent.UpstreamRefreshToken != sessionProto.GetOauthToken().RefreshToken {
			mostRecent.UpstreamRefreshToken = sessionProto.GetOauthToken().RefreshToken
			_, err := s.clientB.GetDataBrokerServiceClient().Put(
				ctx,
				&databroker.PutRequest{
					Records: []*databroker.Record{
						databroker.NewRecord(mostRecent),
					},
				},
			)
			if err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to refresh mcp refresh token from session")
			}
		}
	}
}

// falls back to the most recently modified token when none are usable.
// assumes len(records) > 0.
func mostRecentUsableRefreshToken(
	ctx context.Context,
	records []*databroker.Record,
	now time.Time,
) (*oauth21.MCPRefreshToken, error) {
	records = slices.Filter(records, func(d *databroker.Record) bool {
		return d.GetDeletedAt() == nil
	})

	if len(records) == 0 {
		return nil, backoff.Permanent(ErrNoMCPToken)
	}

	var bestValid, bestAny *oauth21.MCPRefreshToken
	var bestValidAt, bestAnyAt time.Time

	for _, rec := range records {
		token := new(oauth21.MCPRefreshToken)
		if err := rec.GetData().UnmarshalTo(token); err != nil {
			log.Ctx(ctx).Error().Err(err).
				Str("record-id", rec.GetId()).
				Msg("mcp: failed to unmarshal refresh token record")
			continue
		}

		modifiedAt := rec.GetModifiedAt().AsTime()
		if bestAny == nil || modifiedAt.After(bestAnyAt) {
			bestAny, bestAnyAt = token, modifiedAt
		}
		if token.GetRevoked() || !token.GetExpiresAt().AsTime().After(now) {
			continue
		}
		if bestValid == nil || modifiedAt.After(bestValidAt) {
			bestValid, bestValidAt = token, modifiedAt
		}
	}

	if bestValid != nil {
		return bestValid, nil
	}
	return bestAny, nil
}

func indexedFieldFilter(field, value string) (filter *structpb.Struct) {
	filter, _ = structpb.NewStruct(map[string]any{
		field: map[string]any{
			"$eq": value,
		},
	})
	return
}

func (s *sessionTokenSyncer) Run(ctx context.Context) error {
	syncer := databrokerutil.NewSyncer(
		ctx,
		"mcp-session-token-syncer",
		s,
		databrokerutil.WithTypeURL("type.googleapis.com/session.Session"),
		databrokerutil.WithFastForward(),
	)
	return syncer.Run(ctx)
}
