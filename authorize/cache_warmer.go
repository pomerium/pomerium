package authorize

import (
	"context"
	"time"

	"google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

type cacheWarmer struct {
	cc      *grpc.ClientConn
	cache   storage.Cache
	typeURL string

	updatedCC chan *grpc.ClientConn
}

func newCacheWarmer(
	cc *grpc.ClientConn,
	cache storage.Cache,
	typeURL string,
) *cacheWarmer {
	return &cacheWarmer{
		cc:      cc,
		cache:   cache,
		typeURL: typeURL,

		updatedCC: make(chan *grpc.ClientConn, 1),
	}
}

func (cw *cacheWarmer) UpdateConn(cc *grpc.ClientConn) {
	for {
		select {
		case cw.updatedCC <- cc:
			return
		default:
		}
		select {
		case <-cw.updatedCC:
		default:
		}
	}
}

func (cw *cacheWarmer) Run(ctx context.Context) {
	// Run a syncer for the cache warmer until the underlying databroker connection is changed.
	// When that happens cancel the currently running syncer and start a new one.

	runCtx, runCancel := context.WithCancel(ctx)
	go cw.run(runCtx, cw.cc)

	for {
		select {
		case <-ctx.Done():
			runCancel()
			return
		case cc := <-cw.updatedCC:
			if cc != cw.cc {
				log.Ctx(ctx).Info().Msg("cache-warmer: received updated databroker client connection, restarting syncer")
				cw.cc = cc
				runCancel()
				runCtx, runCancel = context.WithCancel(ctx)
				go cw.run(runCtx, cw.cc)
			}
		}
	}
}

func (cw *cacheWarmer) run(ctx context.Context, cc *grpc.ClientConn) {
	log.Ctx(ctx).Debug().Str("type-url", cw.typeURL).Msg("cache-warmer: running databroker syncer to warm cache")
	_ = databroker.NewSyncer(ctx, "cache-warmer", cacheWarmerSyncerHandler{
		client: databroker.NewDataBrokerServiceClient(cc),
		cache:  cw.cache,
	}, databroker.WithTypeURL(cw.typeURL)).Run(ctx)
}

type cacheWarmerSyncerHandler struct {
	client databroker.DataBrokerServiceClient
	cache  storage.Cache
}

func (h cacheWarmerSyncerHandler) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return h.client
}

func (h cacheWarmerSyncerHandler) ClearRecords(_ context.Context) {
	h.cache.InvalidateAll()
}

func (h cacheWarmerSyncerHandler) UpdateRecords(ctx context.Context, serverVersion uint64, records []*databroker.Record) {
	for _, record := range records {
		req := &databroker.QueryRequest{
			Type:  record.Type,
			Limit: 1,
		}
		req.SetFilterByIDOrIndex(record.Id)

		res := &databroker.QueryResponse{
			Records:       []*databroker.Record{record},
			TotalCount:    1,
			ServerVersion: serverVersion,
			RecordVersion: record.Version,
		}

		expiry := time.Now().Add(time.Hour * 24 * 365)
		key, err := storage.MarshalQueryRequest(req)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("cache-warmer: failed to marshal query request")
			continue
		}
		value, err := storage.MarshalQueryResponse(res)
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("cache-warmer: failed to marshal query response")
			continue
		}

		h.cache.Set(expiry, key, value)
	}
}
