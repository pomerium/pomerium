package reconciler

/*
 * Bundle is a representation of a bundle resource
 *
 */

import (
	"sync"
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

// MarkForSyncLater marks the bundle with the given ID for synchronization
// by moving it to the end of the list
func (b *Bundles) MarkForSyncLater(id string) {
	b.Lock()
	defer b.Unlock()

	for i := range b.bundles {
		if b.bundles[i].id == id {
			b.bundles[i].synced = false
			b.bundles[i], b.bundles[len(b.bundles)-1] = b.bundles[len(b.bundles)-1], b.bundles[i]
			return
		}
	}
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
