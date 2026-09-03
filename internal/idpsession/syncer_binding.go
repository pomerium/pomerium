package idpsession

import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"golang.org/x/sync/errgroup"
)

var (
	bindingTypeURLs = []string{
		"type.googleapis.com/session.Session",
		"type.googleapis.com/user.User",
		"type.googleapis.com/oauth21.MCPRefreshToken",
	}
)

func typeURLToSyncSource(typeURL string) syncSource {
	switch typeURL {
	case "type.googleapis.com/session.Session":
		return sourceSessions
	case "type.googleapis.com/user.User":
		return sourceUsers
	case "type.googleapis.com/oauth21.MCPRefreshToken":
		return sourceMCP
	default:
		panic(fmt.Sprintf("%s not yet supported as a binding dependency", typeURL))
	}
}

type bindingSyncer struct {
	clientB    databroker.ClientGetter
	notifier   SyncNotifier
	reconciler *synchronizedReconciler
	dataStore  *dataStore
}

func newBindingSyncer(
	clientB databroker.ClientGetter,
	dataStore *dataStore,
	reconciler *synchronizedReconciler,
) *bindingSyncer {
	return &bindingSyncer{
		clientB:    clientB,
		dataStore:  dataStore,
		notifier:   newSourceNotifier(sourceBindings, reconciler),
		reconciler: reconciler,
	}
}

var _ databrokerutil.SyncerHandler = (*bindingSyncer)(nil)

func (b *bindingSyncer) Run(ctx context.Context) error {
	eg, eCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		syncer := databrokerutil.NewSyncer(
			eCtx,
			"idpsession-binding-syncer",
			b,
			databrokerutil.WithFastForward(),
			databrokerutil.WithTypeURL("type.googleapis.com/idpsession.IDPSessionBinding"),
		)
		return syncer.Run(ctx)
	})

	for _, typeURL := range bindingTypeURLs {
		eg.Go(func() error {
			notifier := newSourceNotifier(typeURLToSyncSource(typeURL), b.reconciler)
			generic := newGenericSyncer(b.clientB, typeURL, b.dataStore, notifier)
			syncer := databrokerutil.NewSyncer(
				eCtx,
				fmt.Sprintf("idpsession-binding-%s-syncer", typeURL),
				generic,
				databrokerutil.WithFastForward(),
				databrokerutil.WithTypeURL(typeURL),
			)
			return syncer.Run(eCtx)
		})
	}

	return eg.Wait()
}

func (b *bindingSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return b.clientB.GetDataBrokerServiceClient()
}

func (b *bindingSyncer) ClearRecords(ctx context.Context) {
	b.notifier.Reset()
	b.dataStore.deleteAllMappings()
}

func (b *bindingSyncer) UpdateRecords(ctx context.Context, _ uint64, recs []*databroker.Record) {
	for _, rec := range recs {
		if err := b.handleBinding(ctx, rec); err != nil {
			log.Ctx(ctx).Err(err).Msg("failed to handle idpsession binding update")
		}
	}
	log.Ctx(ctx).Debug().Msg("triggering sync")
	b.notifier.Updated()
}

func (b *bindingSyncer) handleBinding(_ context.Context, rec *databroker.Record) error {
	binding := &idpsession.IDPSessionBinding{}
	if err := rec.GetData().UnmarshalTo(binding); err != nil {
		return fmt.Errorf("incompatible idpsession binding : %w", err)
	}
	if rec.GetDeletedAt() != nil {
		b.dataStore.deleteMapping(binding)
		return nil
	}
	b.dataStore.updateMapping(binding)
	return nil
}

type genericSyncer struct {
	clientB   databroker.ClientGetter
	typeURL   string
	datastore *dataStore
	notifier  SyncNotifier
}

func newGenericSyncer(
	clientB databroker.ClientGetter,
	typeURL string,
	datastore *dataStore,
	notifier SyncNotifier,
) *genericSyncer {
	return &genericSyncer{
		clientB:   clientB,
		typeURL:   typeURL,
		datastore: datastore,
		notifier:  notifier,
	}
}

var _ databrokerutil.SyncerHandler = (*genericSyncer)(nil)

func (s *genericSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return s.clientB.GetDataBrokerServiceClient()
}

func (s *genericSyncer) ClearRecords(ctx context.Context) {
	log.Ctx(ctx).Info().Str("type-url", s.typeURL).Msg("clearing records")

	s.notifier.Reset()
	s.datastore.deleteRecordType(s.typeURL)
}

func (s *genericSyncer) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
	for _, rec := range records {
		if rec.GetDeletedAt() != nil {
			s.datastore.deleteRecord(rec)
			continue
		}
		s.datastore.addRecord(rec)
	}
	s.notifier.Updated()
}
