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
	"os"

	"github.com/pomerium/pomerium/internal/log"
)

// SyncBundle syncs the bundle to the databroker.
// Databroker holds last synced bundle state in form of a (etag, last-modified) tuple.
// This is only persisted in the databroker after all records are successfully synced.
// That allows us to ignore any changes based on the same bundle state, without need to re-check all records between bundle and databroker.
func (c *service) SyncBundle(ctx context.Context, key string) error {
	var cached, changed BundleCacheEntry
	opts := []DownloadOption{
		WithUpdateCacheEntry(&changed),
	}

	err := c.GetBundleCacheEntry(ctx, key, &cached)
	if err == nil {
		opts = append(opts, WithCacheEntry(cached))
	} else if err != nil && !errors.Is(err, ErrBundleCacheEntryNotFound) {
		return fmt.Errorf("get bundle cache entry: %w", err)
	}

	// download is much faster compared to databroker sync,
	// so we don't use pipe but rather download to a temp file and then sync it to databroker

	fd, err := os.CreateTemp(c.config.tmpDir, fmt.Sprintf("pomerium-bundle-%s", key))
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer fd.Close()
	defer os.Remove(fd.Name())

	err = c.DownloadBundleIfChanged(ctx, fd, key, opts...)
	if err != nil {
		return fmt.Errorf("download bundle: %w", err)
	}

	if changed.Equals(cached) {
		log.Ctx(ctx).Info().Str("bundle", key).Msg("bundle not changed")
		return nil
	}

	_, err = fd.Seek(0, io.SeekStart)
	if err != nil {
		return fmt.Errorf("seek to start: %w", err)
	}

	bundleRecordTypes, err := c.syncBundleToDatabroker(ctx, fd)
	if err != nil {
		return fmt.Errorf("apply bundle to databroker: %w", err)
	}
	changed.RecordTypes = bundleRecordTypes

	log.Ctx(ctx).Info().
		Str("bundle", key).
		Strs("record_types", bundleRecordTypes).
		Str("etag", changed.ETag).
		Time("last_modified", changed.LastModified).
		Msg("bundle synced")

	err = c.SetBundleCacheEntry(ctx, key, changed)
	if err != nil {
		return fmt.Errorf("set bundle cache entry: %w", err)
	}

	return nil
}

func (c *service) syncBundleToDatabroker(ctx context.Context, src io.Reader) ([]string, error) {
	bundleRecords, err := ReadBundleRecords(src)
	if err != nil {
		return nil, fmt.Errorf("read bundle records: %w", err)
	}

	databrokerRecords, err := c.GetDatabrokerRecords(ctx, bundleRecords.RecordTypes())
	if err != nil {
		return nil, fmt.Errorf("get databroker records: %w", err)
	}

	updates := NewDatabrokerChangeSet()

	for _, rec := range databrokerRecords.GetRemoved(bundleRecords).Flatten() {
		updates.Remove(rec.GetType(), rec.GetID())
	}
	for _, rec := range databrokerRecords.GetModified(bundleRecords).Flatten() {
		updates.Upsert(rec.V)
	}
	for _, rec := range databrokerRecords.GetAdded(bundleRecords).Flatten() {
		updates.Upsert(rec.V)
	}

	err = c.ApplyChanges(ctx, updates)
	if err != nil {
		return nil, fmt.Errorf("apply databroker changes: %w", err)
	}

	return bundleRecords.RecordTypes(), nil
}
