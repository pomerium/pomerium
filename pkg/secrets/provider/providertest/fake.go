// Package providertest provides a scripted, thread-safe fake Provider for
// exercising the resolver's cache state machine, scheduling, singleflight, and
// watch behavior without touching a real backend.
package providertest

import (
	"context"
	"sync"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// Fake is a configurable Provider (and Watcher). Responses, blocking, fetch
// counts, and watch notifications are all keyed by ref.FetchKey() so that
// bindings sharing a backend URL share fake state, mirroring the real dedupe.
//
// A Fake is safe for concurrent use.
type Fake struct {
	scheme string

	mu          sync.Mutex
	responses   map[string]response // sticky per-fetchKey response
	def         response            // fallback when a fetchKey has no response
	started     map[string]int      // fetches entered (before any block)
	completed   map[string]int      // fetches returned
	blocks      map[string]chan struct{}
	watchers    map[string]map[int]func() // fetchKey -> id -> notify
	nextWatchID int
	validateErr error
}

type response struct {
	result provider.Result
	err    error
}

// New returns a Fake handling the given scheme. With no scripted response a
// fetch returns provider.ErrNotFound, so tests must opt in to success.
func New(scheme string) *Fake {
	return &Fake{
		scheme:    scheme,
		responses: make(map[string]response),
		def:       response{err: provider.ErrNotFound},
		started:   make(map[string]int),
		completed: make(map[string]int),
		blocks:    make(map[string]chan struct{}),
		watchers:  make(map[string]map[int]func()),
	}
}

var (
	_ provider.Provider = (*Fake)(nil)
	_ provider.Watcher  = (*Fake)(nil)
)

// Scheme implements provider.Provider.
func (f *Fake) Scheme() string { return f.scheme }

// SetValidateErr makes Validate return err (nil clears it).
func (f *Fake) SetValidateErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.validateErr = err
}

// Validate implements provider.Provider.
func (f *Fake) Validate(ref.Ref) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.validateErr
}

// SetValue scripts a successful fetch for fetchKey. Version is set to value so
// the resolver's change detection sees a new version whenever the value changes.
func (f *Fake) SetValue(fetchKey, value string) {
	f.SetResult(fetchKey, provider.Result{Value: []byte(value), Version: value}, nil)
}

// SetResult scripts an arbitrary (Result, error) for fetchKey.
func (f *Fake) SetResult(fetchKey string, r provider.Result, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.responses[fetchKey] = response{result: r, err: err}
}

// SetError scripts an error fetch for fetchKey.
func (f *Fake) SetError(fetchKey string, err error) {
	f.SetResult(fetchKey, provider.Result{}, err)
}

// Fetch implements provider.Provider.
func (f *Fake) Fetch(ctx context.Context, r ref.Ref) (provider.Result, error) {
	key := r.FetchKey()

	f.mu.Lock()
	f.started[key]++
	block := f.blocks[key]
	resp, ok := f.responses[key]
	if !ok {
		resp = f.def
	}
	f.mu.Unlock()

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return provider.Result{}, ctx.Err()
		}
	}

	f.mu.Lock()
	f.completed[key]++
	f.mu.Unlock()

	return resp.result, resp.err
}

// FetchCount returns the number of completed fetches for fetchKey.
func (f *Fake) FetchCount(fetchKey string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.completed[fetchKey]
}

// StartedCount returns the number of fetches that entered (started but possibly
// still blocked) for fetchKey.
func (f *Fake) StartedCount(fetchKey string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.started[fetchKey]
}

// Block causes subsequent fetches for fetchKey to wait until Release.
func (f *Fake) Block(fetchKey string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.blocks[fetchKey] == nil {
		f.blocks[fetchKey] = make(chan struct{})
	}
}

// Release unblocks fetches for fetchKey.
func (f *Fake) Release(fetchKey string) {
	f.mu.Lock()
	ch := f.blocks[fetchKey]
	delete(f.blocks, fetchKey)
	f.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

// Watch implements provider.Watcher.
func (f *Fake) Watch(_ context.Context, r ref.Ref, notify func()) (func(), error) {
	key := r.FetchKey()

	f.mu.Lock()
	id := f.nextWatchID
	f.nextWatchID++
	if f.watchers[key] == nil {
		f.watchers[key] = make(map[int]func())
	}
	f.watchers[key][id] = notify
	f.mu.Unlock()

	return func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		delete(f.watchers[key], id)
	}, nil
}

// TriggerWatch fires all watch notifications registered for fetchKey.
func (f *Fake) TriggerWatch(fetchKey string) {
	f.mu.Lock()
	notifies := make([]func(), 0, len(f.watchers[fetchKey]))
	for _, n := range f.watchers[fetchKey] {
		notifies = append(notifies, n)
	}
	f.mu.Unlock()

	for _, n := range notifies {
		n()
	}
}
