// Package resolver is the secret cache engine. It owns background fetch loops
// (one per distinct backend URL), a refresh-ahead schedule with jitter,
// singleflight de-duplication, stale-while-error and negative caching, and it
// publishes an immutable snapshot behind one atomic pointer so the request hot
// path is a single atomic load plus two map reads.
//
// Fetch loops start on Apply (there is no Run and no readiness gating); the
// service serves from boot and any binding whose first fetch has not yet
// succeeded reads as StateFailed, so requests referencing it fail closed.
package resolver

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sync/singleflight"

	"github.com/pomerium/pomerium/internal/log"
	pommetrics "github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/pkg/secrets/bindings"
	"github.com/pomerium/pomerium/pkg/secrets/provider"
	"github.com/pomerium/pomerium/pkg/secrets/ref"
)

// View is a point-in-time consistent read model. A single evaluation captures
// exactly one View and reads all of its refs from it.
type View interface {
	Lookup(id string) LookupResult
}

// errSuppressed marks a fetch attempt skipped because of the negative cache.
var errSuppressed = errors.New("fetch suppressed by negative cache")

// Resolver is the secret cache engine.
type Resolver struct {
	reg     *provider.Registry
	now     func() time.Time
	rand    func() float64
	logger  zerolog.Logger
	meter   metric.Meter
	metrics *resolverMetrics

	baseCtx    context.Context
	baseCancel context.CancelFunc

	sf singleflight.Group

	mu       sync.Mutex
	closed   bool
	bindings map[string]bindingReg  // binding ID -> reg
	fetches  map[string]*fetchState // fetchKey -> state
	snap     atomic.Pointer[snapshot]
}

type bindingReg struct {
	valueKey    string
	metricLabel string
	scheme      string
}

// Option configures a Resolver.
type Option func(*Resolver)

// WithClock overrides the time source (default time.Now).
func WithClock(now func() time.Time) Option { return func(r *Resolver) { r.now = now } }

// WithRand overrides the jitter source, returning values in [0,1) (default
// math/rand/v2).
func WithRand(rnd func() float64) Option { return func(r *Resolver) { r.rand = rnd } }

// WithLogger overrides the logger.
func WithLogger(l zerolog.Logger) Option { return func(r *Resolver) { r.logger = l } }

// WithMeter overrides the OTel meter (default the global pomerium meter).
func WithMeter(m metric.Meter) Option { return func(r *Resolver) { r.meter = m } }

// New constructs a Resolver. Fetch loops do not start until Apply.
func New(reg *provider.Registry, opts ...Option) *Resolver {
	r := &Resolver{
		reg:      reg,
		now:      time.Now,
		rand:     rand.Float64,
		logger:   *log.Logger(),
		meter:    pommetrics.Meter,
		bindings: make(map[string]bindingReg),
		fetches:  make(map[string]*fetchState),
	}
	for _, o := range opts {
		o(r)
	}
	r.metrics = newResolverMetrics(r.meter, r)
	r.baseCtx, r.baseCancel = context.WithCancel(context.Background())
	r.snap.Store(&snapshot{
		bindings: map[string]bindingInfo{},
		values:   map[string]valueEntry{},
	})
	return r
}

// View returns a point-in-time consistent view via one atomic load.
func (r *Resolver) View() View { return r.snap.Load() }

// Lookup is a convenience for View().Lookup(id).
func (r *Resolver) Lookup(id string) LookupResult { return r.snap.Load().Lookup(id) }

// Close stops every fetch loop and watch. It is idempotent. Reads keep serving
// the last snapshot afterwards.
func (r *Resolver) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	stops := make([]func(), 0, len(r.fetches))
	for _, fs := range r.fetches {
		if fs.watchStop != nil {
			stops = append(stops, fs.watchStop)
		}
	}
	r.mu.Unlock()

	r.baseCancel()
	for _, stop := range stops {
		stop()
	}
}

// valAgg / fetchAgg are the desired-state aggregations built during Apply.
type valAgg struct {
	ref         ref.Ref
	staleGrace  time.Duration
	metricLabel string
}

type fetchAgg struct {
	ref         ref.Ref
	refresh     time.Duration
	negativeTTL time.Duration
	values      map[string]*valAgg // valueKey -> agg
}

// Apply diffs the desired bindings against the running set: it registers new
// fetch keys (starting their loops), unregisters removed ones (stopping loops),
// and updates tuning/value sets on surviving ones without re-fetching a warm
// entry. In-flight requests hold previously-loaded snapshots, so removals are
// safe without a linger delay (immutable snapshots).
func (r *Resolver) Apply(_ context.Context, root *bindings.Scope) {
	var desired []bindings.Binding
	if root != nil {
		desired = root.Effective()
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}

	newBindings := make(map[string]bindingReg, len(desired))
	fetchAggs := make(map[string]*fetchAgg)

	for _, b := range desired {
		fk := b.Ref.FetchKey()
		vk := b.Ref.Key()
		newBindings[b.ID] = bindingReg{valueKey: vk, metricLabel: b.MetricLabel, scheme: b.Ref.Scheme()}

		fa := fetchAggs[fk]
		if fa == nil {
			fa = &fetchAgg{ref: b.Ref, refresh: b.Refresh, negativeTTL: b.NegativeTTL, values: map[string]*valAgg{}}
			fetchAggs[fk] = fa
		} else {
			fa.refresh = min(fa.refresh, b.Refresh)
			fa.negativeTTL = min(fa.negativeTTL, b.NegativeTTL)
		}
		if va := fa.values[vk]; va == nil {
			fa.values[vk] = &valAgg{ref: b.Ref, staleGrace: b.StaleGrace, metricLabel: b.MetricLabel}
		} else {
			va.staleGrace = min(va.staleGrace, b.StaleGrace)
		}
	}

	r.bindings = newBindings

	// Remove fetch keys no longer desired.
	for fk, fs := range r.fetches {
		if _, ok := fetchAggs[fk]; !ok {
			fs.cancel()
			if fs.watchStop != nil {
				fs.watchStop()
			}
			delete(r.fetches, fk)
		}
	}

	// Add or update desired fetch keys.
	for fk, fa := range fetchAggs {
		if fs, ok := r.fetches[fk]; ok {
			r.updateFetchLocked(fs, fa)
		} else {
			r.startFetchLocked(fk, fa)
		}
	}

	r.rebuildSnapshotLocked()
}

// updateFetchLocked reconciles an existing fetch state against desired state.
// A warm value whose valueKey survives is kept and not re-fetched.
func (r *Resolver) updateFetchLocked(fs *fetchState, fa *fetchAgg) {
	fs.refresh = fa.refresh
	fs.negativeTTL = fa.negativeTTL

	for vk, va := range fa.values {
		if vs, ok := fs.values[vk]; ok {
			vs.staleGrace = va.staleGrace
			vs.metricLabel = va.metricLabel
			continue
		}
		vs := &valueState{ref: va.ref, valueKey: vk, staleGrace: va.staleGrace, metricLabel: va.metricLabel, state: StateFailed}
		fs.values[vk] = vs
		r.applyLastPayloadLocked(fs, vs)
	}
	for vk := range fs.values {
		if _, ok := fa.values[vk]; !ok {
			delete(fs.values, vk)
		}
	}
}

// startFetchLocked creates a new fetch state and starts its loop (and watch).
func (r *Resolver) startFetchLocked(fk string, fa *fetchAgg) {
	p, _ := r.reg.Get(fa.ref.Scheme())
	fs := &fetchState{
		fetchKey:    fk,
		fetchRef:    fa.ref,
		provider:    p,
		schemeLabel: fa.ref.Scheme(),
		refresh:     fa.refresh,
		negativeTTL: fa.negativeTTL,
		values:      make(map[string]*valueState, len(fa.values)),
		notifyCh:    make(chan struct{}, 1),
	}
	for vk, va := range fa.values {
		fs.values[vk] = &valueState{ref: va.ref, valueKey: vk, staleGrace: va.staleGrace, metricLabel: va.metricLabel, state: StateFailed}
	}

	ctx, cancel := context.WithCancel(r.baseCtx)
	fs.cancel = cancel
	r.fetches[fk] = fs

	if p == nil {
		// Unknown scheme (should be prevented by config validation): leave all
		// values StateFailed and do not start a loop.
		return
	}

	if w, ok := p.(provider.Watcher); ok {
		notify := func() {
			select {
			case fs.notifyCh <- struct{}{}:
			default:
			}
		}
		if stop, err := w.Watch(ctx, fs.fetchRef, notify); err == nil {
			fs.watchStop = stop
			go r.watchPump(ctx, fs)
		}
	}

	go r.scheduleLoop(ctx, fs)
}

// scheduleLoop performs the initial fetch and then refresh-ahead fetches.
func (r *Resolver) scheduleLoop(ctx context.Context, fs *fetchState) {
	var bo backoffState
	for {
		res, err := r.doFetch(ctx, fs)
		if ctx.Err() != nil {
			return
		}
		wait := r.computeWait(fs, &bo, res, err)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// watchPump turns change hints into immediate (singleflight-collapsed) fetches.
func (r *Resolver) watchPump(ctx context.Context, fs *fetchState) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-fs.notifyCh:
			_, _ = r.doFetch(ctx, fs)
		}
	}
}

// doFetch performs one fetch through singleflight, keyed by FetchKey, so at
// most one provider call per backend URL is in flight regardless of trigger.
// The result is returned to every caller, so the schedule loop can compute the
// next refresh even when its call was collapsed into another's.
func (r *Resolver) doFetch(ctx context.Context, fs *fetchState) (provider.Result, error) {
	leader := false
	v, err, shared := r.sf.Do(fs.fetchKey, func() (any, error) {
		leader = true

		r.mu.Lock()
		negUntil := fs.negativeUntil
		r.mu.Unlock()

		if r.now().Before(negUntil) {
			r.recordNegativeCacheHit(fs)
			return provider.Result{}, errSuppressed
		}

		start := r.now()
		res, ferr := fs.provider.Fetch(ctx, fs.fetchRef)
		dur := r.now().Sub(start)
		r.commitFetch(fs, res, ferr)
		r.recordFetchMetrics(fs, ferr, dur)
		return res, ferr
	})
	if shared && !leader {
		r.recordSingleflightCollapsed(fs)
	}
	res, _ := v.(provider.Result)
	return res, err
}

// computeWait returns how long the schedule loop should sleep before its next
// fetch, given the last outcome.
func (r *Resolver) computeWait(fs *fetchState, bo *backoffState, res provider.Result, err error) time.Duration {
	now := r.now()
	if err != nil {
		if errors.Is(err, errSuppressed) || provider.IsNotFound(err) {
			bo.reset()
			r.mu.Lock()
			nu := fs.negativeUntil
			r.mu.Unlock()
			return max(nu.Sub(now), minInterval)
		}
		return bo.next()
	}
	bo.reset()
	r.mu.Lock()
	refresh := fs.refresh
	r.mu.Unlock()
	return max(nextRefresh(now, res.TTL, refresh, false, r.rand).Sub(now), minInterval)
}

// commitFetch applies a fetch outcome to every value under the FetchKey and
// publishes a new snapshot.
func (r *Resolver) commitFetch(fs *fetchState, res provider.Result, err error) {
	now := r.now()
	r.mu.Lock()
	defer r.mu.Unlock()

	if err != nil {
		if provider.IsNotFound(err) {
			fs.negativeUntil = now.Add(fs.negativeTTL)
			r.logNegativeCacheLocked(fs, now)
		}
		for _, vs := range fs.values {
			r.applyErrorLocked(fs, vs, now, err)
		}
		r.rebuildSnapshotLocked()
		return
	}

	fs.negativeUntil = time.Time{}
	fs.lastVersion = res.Version
	fs.haveVersion = true
	fs.lastRawPayload = append(fs.lastRawPayload[:0], res.Value...)
	fs.haveRawGood = true

	for _, vs := range fs.values {
		selected, serr := ref.ApplySelector(res.Value, vs.ref.Selector())
		if serr != nil {
			// A selector failure is an error for this value only; siblings on
			// the same FetchKey are unaffected.
			r.applyErrorLocked(fs, vs, now, serr)
			continue
		}
		prev := vs.state
		vs.value = selected
		vs.lastGood = now
		vs.state = StateFresh
		vs.lastErrClass = ""
		r.logTransitionLocked(fs, vs, prev, StateFresh)
	}
	r.rebuildSnapshotLocked()
}

// applyErrorLocked transitions one value on a failed fetch/selector.
func (r *Resolver) applyErrorLocked(fs *fetchState, vs *valueState, now time.Time, err error) {
	prev := vs.state
	vs.lastErrClass = errClass(err)

	switch vs.state {
	case StateFresh, StateStale:
		if now.Sub(vs.lastGood) > vs.staleGrace {
			vs.state = StateExpired
			vs.value = nil
		} else {
			vs.state = StateStale
		}
	default: // StateFailed, StateExpired: no servable value, remain
		vs.value = nil
	}

	if vs.state == StateStale {
		r.recordServingStale(vs)
	}
	r.logTransitionLocked(fs, vs, prev, vs.state)
}

// applyLastPayloadLocked populates a newly-added value from the cached raw
// payload, so a config change that adds a selector on an already-fetched URL
// resolves immediately rather than waiting for the next refresh.
func (r *Resolver) applyLastPayloadLocked(fs *fetchState, vs *valueState) {
	if !fs.haveRawGood {
		return
	}
	now := r.now()
	selected, err := ref.ApplySelector(fs.lastRawPayload, vs.ref.Selector())
	if err != nil {
		r.applyErrorLocked(fs, vs, now, err)
		return
	}
	prev := vs.state
	vs.value = selected
	vs.lastGood = now
	vs.state = StateFresh
	r.logTransitionLocked(fs, vs, prev, StateFresh)
}

// rebuildSnapshotLocked publishes a fresh immutable snapshot (copy-on-write).
func (r *Resolver) rebuildSnapshotLocked() {
	snap := &snapshot{
		bindings: make(map[string]bindingInfo, len(r.bindings)),
		values:   make(map[string]valueEntry),
	}
	for id, br := range r.bindings {
		snap.bindings[id] = bindingInfo(br)
	}
	for _, fs := range r.fetches {
		for vk, vs := range fs.values {
			snap.values[vk] = valueEntry{value: secretString(vs.value), state: vs.state}
		}
	}
	r.snap.Store(snap)
}

// logTransitionLocked emits a state-transition log line. It routes through the
// value-free logEvent chokepoint.
func (r *Resolver) logTransitionLocked(fs *fetchState, vs *valueState, prev, cur State) {
	if prev == cur {
		return
	}
	switch cur {
	case StateFresh:
		if !vs.loggedFirst {
			vs.loggedFirst = true
			r.logEvent(zerolog.InfoLevel, fs, vs, "secret resolved")
		} else {
			r.logEvent(zerolog.InfoLevel, fs, vs, "secret recovered")
		}
	case StateStale:
		r.logEvent(zerolog.WarnLevel, fs, vs, "secret serving stale")
	case StateExpired:
		r.logEvent(zerolog.ErrorLevel, fs, vs, "secret expired")
	}
}

func (r *Resolver) logNegativeCacheLocked(fs *fetchState, now time.Time) {
	if !fs.negLoggedAt.IsZero() && now.Sub(fs.negLoggedAt) < fs.negativeTTL {
		return
	}
	fs.negLoggedAt = now
	r.logger.Warn().
		Str("ref", fs.fetchRef.String()).
		Str("error_class", "not_found").
		Msg("secret not found; negative-caching")
}

// logEvent is the single logging chokepoint. It structurally cannot receive a
// secret value: it takes only the fetch/value metadata.
func (r *Resolver) logEvent(level zerolog.Level, fs *fetchState, vs *valueState, msg string) {
	e := r.logger.WithLevel(level).
		Str("ref", fs.fetchRef.String()).
		Str("label", vs.metricLabel).
		Str("state", vs.state.String())
	if vs.lastErrClass != "" {
		e = e.Str("error_class", vs.lastErrClass)
	}
	e.Msg(msg)
}
