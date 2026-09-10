package idpsession

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

type identitySyncer struct {
	clientB databroker.ClientGetter
	store   *changeSetStore
	applier *changeSetApplier
	now     func() time.Time

	notifier SyncNotifier

	refreshManager *refreshManager
}

func newIdentitySyncer(
	clientB databroker.ClientGetter,
	store *changeSetStore,
	applier *changeSetApplier,
	refreshManager *refreshManager,
	notifier SyncNotifier,
	now func() time.Time,
) *identitySyncer {
	return &identitySyncer{
		clientB:        clientB,
		store:          store,
		applier:        applier,
		now:            now,
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
	s.applier.reset()
}

func (s *identitySyncer) UpdateRecords(ctx context.Context, _ uint64, records []*databroker.Record) {
	for _, rec := range records {
		switch rec.GetData().GetTypeUrl() {
		case "type.googleapis.com/idpsession.Binding":
			if err := s.handleBinding(ctx, rec); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to handle binding update")
			}
		case "type.googleapis.com/idpsession.IDPSession":
			if err := s.handleIDPSession(ctx, rec); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to handle idpsession update")
			}
		case "type.googleapis.com/session.Session":
			if err := s.handleSession(ctx, rec); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to handle session update")
			}
		}
	}
	s.notifier.Updated()
}

// handles cleaning up expired sessions
func (s *identitySyncer) handleSession(ctx context.Context, rec *databroker.Record) error {
	if rec.GetDeletedAt() != nil {
		return nil
	}
	sess := &session.Session{}
	if err := rec.GetData().UnmarshalTo(sess); err != nil {
		return fmt.Errorf("incompatible session record %s: %w", rec.GetId(), err)
	}

	if err := sess.Validate(); err != nil {
		newRec := databroker.NewRecord(sess)
		newRec.DeletedAt = timestamppb.Now()
		_, err := s.clientB.GetDataBrokerServiceClient().Put(ctx, &databroker.PutRequest{
			Records: []*databroker.Record{newRec},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *identitySyncer) handleBinding(_ context.Context, rec *databroker.Record) error {
	binding := &idpsession.Binding{}
	if err := rec.GetData().UnmarshalTo(binding); err != nil {
		return fmt.Errorf("incompatible idpsession binding : %w", err)
	}
	if rec.GetDeletedAt() != nil {
		s.store.deleteBinding(binding)
		return nil
	}
	s.applier.onUpdateBinding(binding, s.now())
	return nil
}

func (s *identitySyncer) handleIDPSession(ctx context.Context, rec *databroker.Record) error {
	if rec.GetDeletedAt() != nil {
		s.store.deleteIDPSession(rec.GetId())
		s.refreshManager.cleanUpSchedulers(rec.GetId())
		return nil
	}
	idpSess := &idpsession.IDPSession{}
	if err := rec.GetData().UnmarshalTo(idpSess); err != nil {
		return fmt.Errorf("incompatible idpsession record: %w", err)
	}
	s.applier.onUpdateIDPSession(idpSess, s.now())
	s.refreshManager.onUpdateIDPSession(ctx, idpSess)
	return nil
}
