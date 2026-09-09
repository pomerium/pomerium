package idpsession

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/trace/noop"
	"golang.org/x/sync/errgroup"

	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/identity"
)

type IdentityManager struct {
	clientB        databroker.ClientGetter
	datastore      *dataStore
	refreshManager *refreshManager

	leaseTTL time.Duration
	// The syncer and reconciler run under the same lease.
	identReconciler *synchronizedReconciler
	identitySyncer  *identitySyncer
}

type options struct {
	reconcileInterval time.Duration
	refreshConfig     *RefreshConfig
	now               func() time.Time
	leaseTTL          time.Duration
}

func (o *options) Apply(opts ...Option) {
	for _, opt := range opts {
		opt(o)
	}
}

type Option func(o *options)

func WithReconcileInterval(d time.Duration) Option {
	return func(o *options) {
		o.reconcileInterval = d
	}
}

func WithRefreshConfig(cfg *RefreshConfig) Option {
	return func(o *options) {
		o.refreshConfig = cfg
	}
}

func WithNow(now func() time.Time) Option {
	return func(o *options) {
		o.now = now
	}
}

func WithLeaseTTL(ttl time.Duration) Option {
	return func(o *options) {
		o.leaseTTL = ttl
	}
}

func NewIdentityManagerV2(
	clientB databroker.ClientGetter,
	authenticateGetter func(ctx context.Context, idpID string) (identity.Authenticator, error),
	o ...Option,
) *IdentityManager {
	opts := options{
		reconcileInterval: time.Second * 30,
		now: func() time.Time {
			return time.Now()
		},
		leaseTTL: 30 * time.Second,
		refreshConfig: &RefreshConfig{
			SessionRefreshGracePeriod:         1 * time.Minute,
			SessionRefreshCoolOffDuration:     10 * time.Second,
			UpdateUserInfoInterval:            10 * time.Minute,
			RefreshSessionAtIDTokenExpiration: true,
			TracerProvider:                    noop.TracerProvider{},
			EventMgr:                          events.New(),
			Now:                               time.Now,
			GetAuthenticator:                  authenticateGetter,
		},
	}
	opts.Apply(o...)

	datastore := newDataStore(opts.now)
	reconciler := databrokerutil.NewReconciler(
		clientB,
		datastore.getCurrentChangesetLocked,
		datastore.targetChangeSetLocked,
		func([]*databroker.Record) {},
		bindingCmp,
	)
	synchronizedReconciler := newSynchronizedReconciler(opts.reconcileInterval, reconciler, datastore)
	refreshMgr := newRefreshManager(*opts.refreshConfig, datastore, clientB)

	return &IdentityManager{
		identReconciler: synchronizedReconciler,
		clientB:         clientB,
		datastore:       datastore,
		refreshManager:  refreshMgr,
		identitySyncer:  newIdentitySyncer(clientB, datastore, refreshMgr, synchronizedReconciler),
		leaseTTL:        opts.leaseTTL,
	}
}

func (s *IdentityManager) UpdateRefreshConfig(ctx context.Context, refreshConfig *RefreshConfig) {
	s.refreshManager.updateConfig(ctx, *refreshConfig)
}

func (s *IdentityManager) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return s.clientB.GetDataBrokerServiceClient()
}

// Run runs the manager. This method blocks until an error occurs or the given context is canceled.
func (s *IdentityManager) Run(ctx context.Context) error {
	leaser := databrokerutil.NewLeaser(
		"identity_manager_v2",
		s.leaseTTL,
		s,
	)
	return leaser.Run(ctx)
}

func (s *IdentityManager) RunLeased(ctx context.Context) error {
	eg, eCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		return s.identReconciler.Run(eCtx)
	})
	eg.Go(func() error {
		return s.identitySyncer.Run(eCtx)
	})
	return eg.Wait()
}
