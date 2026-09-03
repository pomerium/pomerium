package idpsession

import (
	"context"
	"sync"
	"time"

	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/identity"
	"golang.org/x/sync/errgroup"
)

type IdentityManager struct {
	clientB   databroker.ClientGetter
	datastore *dataStore
	mu        sync.Mutex

	//!! assumes these three are running under the same lease
	identReconciler  *synchronizedReconciler
	idpSessionSyncer *idpSessionSyncer
	bindingSyncer    *bindingSyncer
}

type options struct {
	reconcileInterval time.Duration
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

func NewIdentityManager(
	clientB databroker.ClientGetter,
	authenticateGetter func(ctx context.Context, idpID string) (identity.Authenticator, error),
	o ...Option,
) *IdentityManager {
	opts := options{
		reconcileInterval: time.Second * 30,
	}
	opts.Apply(o...)

	datastore := newDataStore()
	reconciler := databrokerutil.NewReconciler(
		clientB,
		datastore.getCurrentChangesetLocked,
		datastore.targetChangeSetLocked,
		func([]*databroker.Record) {},
		bindingCmp,
	)
	synchronizedReconciler := newSynchronizedReconciler(opts.reconcileInterval, reconciler, datastore)

	return &IdentityManager{
		identReconciler: synchronizedReconciler,
		clientB:         clientB,
		datastore:       datastore,
		bindingSyncer:   newBindingSyncer(clientB, datastore, synchronizedReconciler),
		idpSessionSyncer: newIdpSessionSyncer(
			clientB,
			authenticateGetter,
			datastore,
			newSourceNotifier(sourceIDPSessions, synchronizedReconciler),
		),
	}
}

func (s *IdentityManager) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return s.clientB.GetDataBrokerServiceClient()
}

// Run runs the manager. This method blocks until an error occurs or the given context is canceled.
func (s *IdentityManager) Run(ctx context.Context) error {
	leaser := databrokerutil.NewLeaser(
		"identity_manager_v2",
		// TODO : config controlled.
		time.Second*30,
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
		return s.bindingSyncer.Run(eCtx)
	})

	eg.Go(func() error {
		return s.idpSessionSyncer.Run(eCtx)
	})

	return eg.Wait()
}
