package idpsession

import (
	"context"
	"sync"
	"time"

	"github.com/hashicorp/go-set/v3"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
)

type syncSource string

const (
	sourceIDPSessions syncSource = "idp-sessions"
	sourceBindings    syncSource = "bindings"
	sourceSessions    syncSource = "sessions"
	sourceUsers       syncSource = "users"
	sourceMCP         syncSource = "mcp-refresh-tokens"
)

type synchronizedReconciler struct {
	mu sync.Mutex

	reconciler databrokerutil.Reconciler
	required   *set.Set[syncSource]
	ready      *set.Set[syncSource]

	// reconcileLocker mutex. Prevents races between readiness check &
	// potential concurrent syncer Clear invocations
	reconcileLocker sync.Locker

	wake chan struct{}
}

func newSynchronizedReconciler(
	reconciler databrokerutil.Reconciler,
	ds sync.Locker,
) *synchronizedReconciler {
	syncSources := []syncSource{
		sourceIDPSessions,
		sourceBindings,
		sourceSessions,
		sourceUsers,
		sourceMCP,
	}
	required := set.From(syncSources)
	return &synchronizedReconciler{
		required:        required,
		ready:           set.New[syncSource](len(syncSources)),
		wake:            make(chan struct{}, 1),
		reconciler:      reconciler,
		reconcileLocker: ds,
	}
}

func (r *synchronizedReconciler) isReady() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.ready.Equal(r.required)
}

func (r *synchronizedReconciler) Updated(source syncSource) {
	r.mu.Lock()
	r.ready.Insert(source)
	r.mu.Unlock()
	r.wakeup()
}

func (r *synchronizedReconciler) Reset(source syncSource) {
	r.mu.Lock()
	r.ready.Remove(source)
	r.mu.Unlock()
	r.wakeup()
}

func (r *synchronizedReconciler) wakeup() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *synchronizedReconciler) Run(ctx context.Context) error {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-r.wake:
		case <-ticker.C:
		}
		// !! critical path. Prevents a wakeup trigger and a Clear trigger racing while the reconciler runs.
		r.reconcileLocker.Lock()
		if !r.isReady() {
			r.reconcileLocker.Unlock()
			log.Ctx(ctx).Debug().Msg("reconciler not yet ready")
			continue
		}

		// if a clear happens here or in between getCurrent and getTarget in the reconcile loop
		// then we could accidentally wipe huge amounts of things if we weren't locked.

		if err := r.reconciler.Reconcile(ctx); err != nil {
			log.Ctx(ctx).Err(err).Msg("reconcile")
		}
		r.reconcileLocker.Unlock()
	}
}

type SyncNotifier interface {
	Reset()
	Updated()
}

type sourceNotifier struct {
	source syncSource
	owner  *synchronizedReconciler
}

func newSourceNotifier(source syncSource, reconciler *synchronizedReconciler) SyncNotifier {
	return &sourceNotifier{
		source: source,
		owner:  reconciler,
	}
}

func (s *sourceNotifier) Reset() {
	s.owner.Reset(s.source)
}

func (s *sourceNotifier) Updated() {
	s.owner.Updated(s.source)
}
