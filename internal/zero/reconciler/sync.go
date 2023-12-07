package reconciler

/*
 * Sync syncs the bundles between their cloud source and the databroker.
 *
 * FullSync performs a full sync of the bundles by calling the API,
 * and walking the list of bundles, and calling SyncBundle on each.
 * It also removes any records in the databroker that are not in the list of bundles.
 *
 * WatchAndSync watches the API for changes, and calls SyncBundle on each change.
 *
 */

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/retry"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

// Sync synchronizes the bundles between their cloud source and the databroker.
func (c *service) SyncLoop(ctx context.Context) error {
	ticker := time.NewTicker(c.periodicUpdateInterval.Load())
	defer ticker.Stop()

	for {
		dur := c.periodicUpdateInterval.Load()
		ticker.Reset(dur)

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-c.bundleSyncRequest:
			log.Ctx(ctx).Info().Msg("bundle sync triggered")
			err := c.syncBundles(ctx)
			if err != nil {
				return fmt.Errorf("reconciler: sync bundles: %w", err)
			}
		case <-c.fullSyncRequest:
			log.Ctx(ctx).Info().Msg("full sync triggered")
			err := c.syncAll(ctx)
			if err != nil {
				return fmt.Errorf("reconciler: sync all: %w", err)
			}
		case <-ticker.C:
			log.Ctx(ctx).Info().Msg("periodic sync triggered")
			err := c.syncAll(ctx)
			if err != nil {
				return fmt.Errorf("reconciler: sync all: %w", err)
			}
		}
	}
}

func (c *service) syncAll(ctx context.Context) error {
	err := c.syncBundleList(ctx)
	if err != nil {
		return fmt.Errorf("sync bundle list: %w", err)
	}

	err = c.syncBundles(ctx)
	if err != nil {
		return fmt.Errorf("sync bundles: %w", err)
	}

	return nil
}

// trySyncAllBundles tries to sync all bundles in the queue.
func (c *service) syncBundleList(ctx context.Context) error {
	// refresh bundle list,
	// ignoring other signals while we're retrying
	return retry.Retry(ctx,
		"refresh bundle list", c.refreshBundleList,
		retry.WithWatch("refresh bundle list", c.fullSyncRequest, nil),
		retry.WithWatch("bundle update", c.bundleSyncRequest, nil),
	)
}

// syncBundles retries until there are no more bundles to sync.
// updates bundle list if the full bundle update request arrives.
func (c *service) syncBundles(ctx context.Context) error {
	return retry.Retry(ctx,
		"sync bundles", c.trySyncBundles,
		retry.WithWatch("refresh bundle list", c.fullSyncRequest, c.refreshBundleList),
		retry.WithWatch("bundle update", c.bundleSyncRequest, nil),
	)
}

// trySyncAllBundles tries to sync all bundles in the queue
// it returns nil if all bundles were synced successfully
func (c *service) trySyncBundles(ctx context.Context) error {
	for {
		id, ok := c.bundles.GetNextBundleToSync()
		if !ok { // no more bundles to sync
			return nil
		}

		err := c.syncBundle(ctx, id)
		if err != nil {
			c.bundles.MarkForSyncLater(id)
			return fmt.Errorf("sync bundle %s: %w", id, err)
		}
	}
}

// syncBundle syncs the bundle to the databroker.
// Databroker holds last synced bundle state in form of a (etag, last-modified) tuple.
// This is only persisted in the databroker after all records are successfully synced.
// That allows us to ignore any changes based on the same bundle state, without need to re-check all records between bundle and databroker.
func (c *service) syncBundle(ctx context.Context, key string) error {
	cached, err := c.GetBundleCacheEntry(ctx, key)
	if err != nil && !errors.Is(err, ErrBundleCacheEntryNotFound) {
		return fmt.Errorf("get bundle cache entry: %w", err)
	}

	// download is much faster compared to databroker sync,
	// so we don't use pipe but rather download to a temp file and then sync it to databroker
	fd, err := c.GetTmpFile(key)
	if err != nil {
		return fmt.Errorf("get tmp file: %w", err)
	}
	defer func() {
		if err := fd.Close(); err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("close tmp file")
		}
	}()

	conditional := cached.GetDownloadConditional()
	log.Ctx(ctx).Debug().Str("id", key).Any("conditional", conditional).Msg("downloading bundle")

	result, err := c.config.api.DownloadClusterResourceBundle(ctx, fd, key, conditional)
	if err != nil {
		c.ReportBundleAppliedFailure(ctx, key, BundleStatusFailureDownloadError, err)
		return fmt.Errorf("download bundle: %w", err)
	}

	if result.NotModified {
		log.Ctx(ctx).Debug().Str("bundle", key).Msg("bundle not changed")
		return nil
	}

	log.Ctx(ctx).Debug().Str("bundle", key).
		Interface("cached-entry", cached).
		Interface("current-entry", result.DownloadConditional).
		Msg("bundle updated")

	_, err = fd.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("seek to start: %w", err)
	}

	bundleRecordTypes, err := c.syncBundleToDatabroker(ctx, key, fd, cached.GetRecordTypes())
	if err != nil {
		c.ReportBundleAppliedFailure(ctx, key, BundleStatusFailureDatabrokerError, err)
		return fmt.Errorf("apply bundle to databroker: %w", err)
	}
	current := BundleCacheEntry{
		DownloadConditional: *result.DownloadConditional,
		RecordTypes:         bundleRecordTypes,
	}

	log.Ctx(ctx).Info().
		Str("bundle", key).
		Strs("record_types", bundleRecordTypes).
		Str("etag", current.ETag).
		Str("last_modified", current.LastModified).
		Interface("metadata", result.Metadata).
		Msg("bundle synced")

	err = c.SetBundleCacheEntry(ctx, key, current)
	if err != nil {
		err = fmt.Errorf("set bundle cache entry: %w", err)
		c.ReportBundleAppliedFailure(ctx, key, BundleStatusFailureDatabrokerError, err)
		return err
	}

	c.ReportBundleAppliedSuccess(ctx, key, result.Metadata)
	return nil
}

func strUnion(a, b []string) []string {
	m := make(map[string]struct{}, len(a)+len(b))
	for _, s := range a {
		m[s] = struct{}{}
	}
	for _, s := range b {
		m[s] = struct{}{}
	}

	out := make([]string, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	return out
}

func (c *service) syncBundleToDatabroker(ctx context.Context, key string, src io.Reader, currentRecordTypes []string) ([]string, error) {
	bundleRecords, err := ReadBundleRecords(src)
	if err != nil {
		return nil, fmt.Errorf("read bundle records: %w", err)
	}

	databrokerRecords, err := GetDatabrokerRecords(ctx,
		c.config.databrokerClient,
		strUnion(bundleRecords.RecordTypes(), currentRecordTypes),
	)
	if err != nil {
		return nil, fmt.Errorf("get databroker records: %w", err)
	}

	err = databroker.NewReconciler(
		fmt.Sprintf("bundle-%s", key),
		c.config.databrokerClient,
		func(ctx context.Context) (databroker.RecordSetBundle, error) {
			return databrokerRecords, nil
		},
		func(ctx context.Context) (databroker.RecordSetBundle, error) {
			return bundleRecords, nil
		},
		func(_ []*databroker.Record) {},
		EqualRecord,
	).Reconcile(ctx)
	if err != nil {
		return nil, fmt.Errorf("reconcile databroker records: %w", err)
	}

	return bundleRecords.RecordTypes(), nil
}

func (c *service) refreshBundleList(ctx context.Context) error {
	resp, err := c.config.api.GetClusterResourceBundles(ctx)
	if err != nil {
		return fmt.Errorf("get bundles: %w", err)
	}

	ids := make([]string, 0, len(resp.Bundles))
	for _, v := range resp.Bundles {
		ids = append(ids, v.Id)
	}

	c.bundles.Set(ids)
	return nil
}
