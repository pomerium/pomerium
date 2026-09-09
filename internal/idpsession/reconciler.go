package idpsession

import (
	"context"
	"sync"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
)

type synchronizedReconciler struct {
	mu              sync.Mutex
	ready           bool
	reconciler      databrokerutil.Reconciler
	reconcileLocker sync.Locker
	interval        time.Duration
	wake            chan struct{}
}

func newSynchronizedReconciler(interval time.Duration, reconciler databrokerutil.Reconciler, ds sync.Locker) *synchronizedReconciler {
	return &synchronizedReconciler{
		reconciler:      reconciler,
		reconcileLocker: ds,
		interval:        interval,
		wake:            make(chan struct{}, 1),
	}
}

func (r *synchronizedReconciler) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ready = false
}

func (r *synchronizedReconciler) Updated() {
	r.mu.Lock()
	r.ready = true
	r.mu.Unlock()
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

func (r *synchronizedReconciler) Run(ctx context.Context) error {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-r.wake:
		case <-ticker.C:
		}
		r.reconcile(ctx)
	}
}

func (r *synchronizedReconciler) reconcile(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.ready {
		return
	}

	r.reconcileLocker.Lock()
	defer r.reconcileLocker.Unlock()
	// !! critical path. Prevents a wakeup trigger and a Clear trigger racing while the reconciler runs.
	if err := r.reconciler.Reconcile(ctx); err != nil {
		log.Ctx(ctx).Err(err).Msg("reconcile")
	}
}

type SyncNotifier interface {
	Reset()
	Updated()
}

var _ SyncNotifier = (*synchronizedReconciler)(nil)
