package idpsession

import (
	"context"
	"fmt"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
)

type identitySyncer struct {
	clientB   databroker.ClientGetter
	dataStore *dataStore

	notifier SyncNotifier

	refreshManager *refreshManager
}

func newIdentitySyncer(clientB databroker.ClientGetter, ds *dataStore, refreshManager *refreshManager, notifier SyncNotifier) *identitySyncer {
	return &identitySyncer{
		clientB:        clientB,
		dataStore:      ds,
		notifier:       notifier,
		refreshManager: refreshManager,
	}
}

func (s *identitySyncer) Run(ctx context.Context) error {
	syncer := databrokerutil.NewSyncer(ctx, "identity-manager-v2", s, databrokerutil.WithFastForward())
	defer syncer.Close()
	return syncer.Run(ctx)
}

var _ databrokerutil.SyncerHandler = (*identitySyncer)(nil)

func (s *identitySyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return s.clientB.GetDataBrokerServiceClient()
}

func (s *identitySyncer) ClearRecords(ctx context.Context) {
	log.Ctx(ctx).Info().Msg("clearing records")
	s.notifier.Reset()
	s.refreshManager.Close()
	s.dataStore.reset()
}

func (s *identitySyncer) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
	for _, rec := range records {
		switch rec.GetData().GetTypeUrl() {
		case "type.googleapis.com/user.User":
			fallthrough
		case "type.googleapis.com/session.Session":
			fallthrough
		case "type.googleapis.com/oauth21.MCPRefreshToken":
			s.handleBoundRecord(ctx, rec)
		case "type.googleapis.com/idpsession.Binding":
			if err := s.handleBinding(ctx, rec); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to handle binding update")
			}
		case "type.googleapis.com/idpsession.IDPSession":
			if err := s.handleIDPSession(ctx, rec); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to handle idpsession update")
			}
		default:
		}
	}
	s.notifier.Updated()
}

func (s *identitySyncer) handleBoundRecord(_ context.Context, rec *databroker.Record) {
	if rec.GetDeletedAt() != nil {
		s.dataStore.deleteRecord(rec)
		return
	}
	s.dataStore.addRecord(rec)
}

func (s *identitySyncer) handleBinding(_ context.Context, rec *databroker.Record) error {
	binding := &idpsession.Binding{}
	if err := rec.GetData().UnmarshalTo(binding); err != nil {
		return fmt.Errorf("incompatible idpsession binding : %w", err)
	}
	if rec.GetDeletedAt() != nil {
		s.dataStore.deleteMapping(binding)
		s.dataStore.deleteRecord(rec)
		return nil
	}
	s.dataStore.updateMapping(binding)
	s.dataStore.addRecord(rec)
	return nil
}

func (s *identitySyncer) handleIDPSession(ctx context.Context, rec *databroker.Record) error {
	if rec.GetDeletedAt() != nil {
		s.dataStore.deleteIDPSession(rec.GetId())
		s.refreshManager.cleanUpSchedulers(rec.GetId())
		return nil
	}
	idpSess := &idpsession.IDPSession{}
	if err := rec.GetData().UnmarshalTo(idpSess); err != nil {
		return fmt.Errorf("incompatible idpsession record: %w", err)
	}
	s.dataStore.putIDPSession(idpSess)
	s.refreshManager.onUpdateIDPSession(ctx, idpSess)
	return nil
}
