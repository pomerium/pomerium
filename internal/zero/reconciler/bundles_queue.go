package reconciler

import (
	"container/heap"
	"sync"
)

type bundle struct {
	id       string
	synced   bool
	priority int
}

type bundleHeap []bundle

func (h bundleHeap) Len() int { return len(h) }
func (h bundleHeap) Less(i, j int) bool {
	// If one is synced and the other is not, the unsynced one comes first
	if h[i].synced != h[j].synced {
		return !h[i].synced
	}
	// Otherwise, the one with the lower priority comes first
	return h[i].priority < h[j].priority
}

func (h bundleHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

func (h *bundleHeap) Push(x interface{}) {
	item := x.(bundle)
	*h = append(*h, item)
}

func (h *bundleHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

// BundleQueue is a priority queue of bundles to sync.
type BundleQueue struct {
	sync.Mutex
	bundles bundleHeap
	counter int // to assign priorities based on order of insertion
}

// Set sets the bundles to be synced. This will reset the sync status of all bundles.
func (b *BundleQueue) Set(bundles []string) {
	b.Lock()
	defer b.Unlock()

	b.bundles = make(bundleHeap, len(bundles))
	b.counter = len(bundles)
	for i, id := range bundles {
		b.bundles[i] = bundle{
			id:       id,
			synced:   false,
			priority: i,
		}
	}
	heap.Init(&b.bundles)
}

// MarkForSync marks the bundle with the given ID for syncing.
func (b *BundleQueue) MarkForSync(id string) {
	b.Lock()
	defer b.Unlock()

	for i, bundle := range b.bundles {
		if bundle.id == id {
			b.bundles[i].synced = false
			heap.Fix(&b.bundles, i)
			return
		}
	}

	newBundle := bundle{id: id, synced: false, priority: b.counter}
	heap.Push(&b.bundles, newBundle)
	b.counter++
}

// MarkForSyncLater marks the bundle with the given ID for syncing later (after all other bundles).
func (b *BundleQueue) MarkForSyncLater(id string) {
	b.Lock()
	defer b.Unlock()

	for i, bundle := range b.bundles {
		if bundle.id != id {
			continue
		}

		// Increase the counter first to ensure that this bundle has the highest (last) priority.
		b.counter++
		b.bundles[i].synced = false
		b.bundles[i].priority = b.counter
		heap.Fix(&b.bundles, i)
		return
	}
}

// GetNextBundleToSync returns the ID of the next bundle to sync and whether there is one.
func (b *BundleQueue) GetNextBundleToSync() (string, bool) {
	b.Lock()
	defer b.Unlock()

	if len(b.bundles) == 0 {
		return "", false
	}

	// Check the top bundle without popping
	if b.bundles[0].synced {
		return "", false
	}

	// Mark the top bundle as synced and push it to the end
	id := b.bundles[0].id
	b.bundles[0].synced = true
	b.bundles[0].priority = b.counter
	heap.Fix(&b.bundles, 0)
	b.counter++

	return id, true
}
