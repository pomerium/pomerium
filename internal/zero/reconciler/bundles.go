package reconciler

/*
 * Bundle is a representation of a bundle resource
 *
 */

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"
)

type bundle struct {
	id     string
	synced bool
}

// Bundles is a list of bundles to sync
type Bundles struct {
	sync.Mutex
	bundles []bundle
}

// Set sets the list of bundles to sync.
// bundles would be synced in the order they are provided.
func (b *Bundles) Set(bundles []string) {
	b.Lock()
	defer b.Unlock()

	b.bundles = make([]bundle, len(bundles))
	for i, id := range bundles {
		b.bundles[i] = bundle{id: id, synced: false}
	}
}

// MarkForSync marks the bundle with the given ID for synchronization
// if bundle does not exist, it is added to the end of the list as we do not know its relative priority.
// we will have just a handful of bundles, so it is not a big deal to scan the list on each (infrequent) update.
func (b *Bundles) MarkForSync(id string) {
	b.Lock()
	defer b.Unlock()

	for i := range b.bundles {
		if b.bundles[i].id == id {
			b.bundles[i].synced = false
			return
		}
	}

	b.bundles = append(b.bundles, bundle{id: id, synced: false})
}

// GetNextBundleToSync returns the next bundle to sync.
// If there is no bundle to sync, it returns false.
func (b *Bundles) GetNextBundleToSync() (string, bool) {
	b.Lock()
	defer b.Unlock()

	for i, bundle := range b.bundles {
		if !bundle.synced {
			b.bundles[i].synced = true
			return bundle.id, true
		}
	}
	return "", false
}

// GetBundles returns the list of bundles that have to be present in the cluster.
func (c *service) RefreshBundleList(ctx context.Context) error {
	resp, err := c.config.clusterAPI.GetClusterResourceBundlesWithResponse(ctx)
	if err != nil {
		return fmt.Errorf("get bundles: %w", err)
	}
	if resp.JSON200 == nil {
		return fmt.Errorf("get bundles: unexpected response: %d/%s", resp.StatusCode(), resp.Status())
	}

	ids := make([]string, 0, len(resp.JSON200.Bundles))
	for _, v := range resp.JSON200.Bundles {
		ids = append(ids, v.Id)
	}

	c.bundles.Set(ids)
	return nil
}

// GetBundleDownloadURL returns the up to date download URL for the given bundle.
func (c *service) GetBundleDownloadURL(ctx context.Context, key string) (*url.URL, error) {
	entry, ok := c.downloadURLCache[key]
	if ok && entry.ExpiresAt.After(time.Now().Add(c.config.minDownloadTTL)) {
		return &entry.URL, nil
	}

	delete(c.downloadURLCache, key)

	p, err := c.getBundleDownloadURLFromAPI(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("get bundle download url (from api): %w", err)
	}

	c.downloadURLCache[key] = *p
	return &p.URL, nil
}

func (c *service) getBundleDownloadURLFromAPI(ctx context.Context, key string) (*urlEntry, error) {
	now := time.Now()

	resp, err := c.config.clusterAPI.DownloadClusterResourceBundleWithResponse(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("api: %w", err)
	}
	if resp.JSON200 == nil {
		return nil, fmt.Errorf("unexpected api response: %d/%s", resp.StatusCode(), resp.Status())
	}

	expiresSeconds, err := strconv.ParseInt(resp.JSON200.ExpiresInSeconds, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse expiration: %w", err)
	}

	u, err := url.Parse(resp.JSON200.Url)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	return &urlEntry{
		URL:       *u,
		ExpiresAt: now.Add(time.Duration(expiresSeconds) * time.Second),
	}, nil
}
