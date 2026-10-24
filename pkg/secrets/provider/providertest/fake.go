// Package providertest provides a scripted, thread-safe fake Provider for
// exercising the resolver's cache state machine, scheduling, singleflight, and
// watch behavior without touching a real backend.
package providertest

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/zeebo/xxh3"

	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// Fake is a configurable Provider (and Watcher). Responses, blocking, fetch
// counts, and watch notifications are all keyed by ref.FetchKey() so that
// bindings sharing a backend URL share fake state, mirroring the real dedupe.
//
// A Fake is safe for concurrent use, and the zero value is usable: it handles
// the empty scheme and every fetchKey is unscripted.
type Fake struct {
	scheme string

	mu          sync.Mutex
	responses   map[string]response // sticky per-fetchKey response
	started     map[string]int      // fetches entered (before any block)
	completed   map[string]int      // fetches returned
	blocks      map[string]chan struct{}
	watchers    map[string]map[int]*watchReg // fetchKey -> id -> registration
	nextWatchID int
	validateErr error
}

type response struct {
	result provider.Result
	err    error
}

type watchReg struct {
	notify  func()
	stopped atomic.Bool // set by teardown before the registration is dropped
}

// New returns a Fake handling the given scheme. With no scripted response a
// fetch returns provider.ErrNotFound, so tests must opt in to success.
func New(scheme string) *Fake {
	return &Fake{scheme: scheme}
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

// SetValue scripts a successful fetch for fetchKey. Version is a content hash
// of value, so the resolver's change detection sees a new version whenever the
// value changes, without provider.Result.Version (which is meant for logs and
// metrics) ever carrying secret material.
func (f *Fake) SetValue(fetchKey, value string) {
	version := strconv.FormatUint(xxh3.HashString(value), 16)
	f.SetResult(fetchKey, provider.Result{Value: []byte(value), Version: version}, nil)
}

// SetResult scripts an arbitrary (Result, error) for fetchKey.
func (f *Fake) SetResult(fetchKey string, r provider.Result, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.responses == nil {
		f.responses = make(map[string]response)
	}
	f.responses[fetchKey] = response{result: r, err: err}
}

// SetError scripts an error fetch for fetchKey.
func (f *Fake) SetError(fetchKey string, err error) {
	f.SetResult(fetchKey, provider.Result{}, err)
}

// Fetch implements provider.Provider. Like the real file provider it refuses
// an already-done context without consulting the backend, so a fetch cancelled
// before it starts counts as neither started nor completed.
func (f *Fake) Fetch(ctx context.Context, r ref.Ref) (provider.Result, error) {
	key := r.FetchKey()

	if err := ctx.Err(); err != nil {
		return provider.Result{}, err
	}

	f.mu.Lock()
	if f.started == nil {
		f.started = make(map[string]int)
	}
	f.started[key]++
	block := f.blocks[key]
	resp, ok := f.responses[key]
	if !ok {
		// Unscripted keys are not-found, so tests must opt in to success.
		resp = response{err: provider.ErrNotFound}
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
	if f.completed == nil {
		f.completed = make(map[string]int)
	}
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
	if f.blocks == nil {
		f.blocks = make(map[string]chan struct{})
	}
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

// Watch implements provider.Watcher. As the interface requires (and as the
// real file provider does), the registration is dropped when ctx is done as
// well as when the returned stop func is called, so a test that stops a watch
// by cancelling its context behaves the same against the Fake and the real
// provider.
func (f *Fake) Watch(ctx context.Context, r ref.Ref, notify func()) (func(), error) {
	key := r.FetchKey()

	f.mu.Lock()
	id := f.nextWatchID
	f.nextWatchID++
	if f.watchers == nil {
		f.watchers = make(map[string]map[int]*watchReg)
	}
	if f.watchers[key] == nil {
		f.watchers[key] = make(map[int]*watchReg)
	}
	reg := &watchReg{notify: notify}
	f.watchers[key][id] = reg
	f.mu.Unlock()

	teardown := func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		reg.stopped.Store(true)
		delete(f.watchers[key], id)
	}
	cancelAfter := context.AfterFunc(ctx, teardown)
	return func() {
		cancelAfter()
		teardown()
	}, nil
}

// TriggerWatch fires all watch notifications registered for fetchKey.
// Callbacks run outside the lock so they may call Watch or a stop func; as
// provider.Watcher requires, a registration stopped by an earlier callback in
// the same round is skipped.
func (f *Fake) TriggerWatch(fetchKey string) {
	f.mu.Lock()
	regs := make([]*watchReg, 0, len(f.watchers[fetchKey]))
	for _, reg := range f.watchers[fetchKey] {
		regs = append(regs, reg)
	}
	f.mu.Unlock()

	for _, reg := range regs {
		if !reg.stopped.Load() {
			reg.notify()
		}
	}
}
