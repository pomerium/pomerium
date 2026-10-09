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
	"github.com/pomerium/pomerium/pkg/grpc/user"
)

type identitySyncer struct {
	clientB databroker.ClientGetter
	now     func() time.Time

	notifier SyncNotifier

	idx IdentityIndex

	refreshManager *refreshManager
}

func newIdentitySyncer(
	clientB databroker.ClientGetter,
	idx IdentityIndex,
	refreshManager *refreshManager,
	notifier SyncNotifier,
	now func() time.Time,
) *identitySyncer {
	return &identitySyncer{
		clientB:        clientB,
		idx:            idx,
		now:            now,
		notifier:       notifier,
		refreshManager: refreshManager,
	}
}

func (s *identitySyncer) Run(ctx context.Context) error {
	syncer := databrokerutil.NewSyncer(ctx, "identity-manager-v2", s)
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
	s.idx.Reset()
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
		case "type.googleapis.com/user.User":
			if err := s.handleUser(ctx, rec); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to handle user update")
			}
		}
	}
	s.notifier.Updated()
}

func (s *identitySyncer) handleUser(_ context.Context, rec *databroker.Record) error {
	if rec.GetDeletedAt() != nil {
		s.idx.DeleteUser(rec.GetId())
		return nil
	}
	u := &user.User{}
	if err := rec.GetData().UnmarshalTo(u); err != nil {
		return err
	}
	s.idx.PutUser(u)
	return nil
}

// handles cleaning up expired sessions
func (s *identitySyncer) handleSession(ctx context.Context, rec *databroker.Record) error {
	if rec.GetDeletedAt() != nil {
		log.Ctx(ctx).Trace().Str("binding-id", rec.GetId()).Msg("deleted session schedules binding revocation")
		s.idx.DeleteBinding(rec.GetId(), s.now())
		return nil
	}
	sess := &session.Session{}
	if err := rec.GetData().UnmarshalTo(sess); err != nil {
		return fmt.Errorf("incompatible session record %s: %w", rec.GetId(), err)
	}

	if err := sess.Validate(); err != nil {
		log.Ctx(ctx).Trace().Str("session-id", rec.GetId()).Msg("expired session schedules session deletion")
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

func (s *identitySyncer) handleBinding(ctx context.Context, rec *databroker.Record) error {
	binding := &idpsession.Binding{}
	if err := rec.GetData().UnmarshalTo(binding); err != nil {
		return fmt.Errorf("incompatible idpsession binding : %w", err)
	}
	if rec.GetDeletedAt() != nil {
		log.Ctx(ctx).Trace().Str("binding-id", binding.GetId()).Msg("deleted binding schedules revocation")
		s.idx.DeleteBinding(rec.GetId(), s.now())
		return nil
	}

	if binding.GetIdpSessionId() == "" || binding.GetId() == "" {
		log.Ctx(ctx).Info().Str("record-id", rec.GetId()).Str("type-url", rec.GetData().GetTypeUrl()).
			Msg("invalid binding observed, cleaning up")
		rec.DeletedAt = timestamppb.New(s.now())
		_, err := s.clientB.GetDataBrokerServiceClient().Put(ctx, &databroker.PutRequest{Records: []*databroker.Record{rec}})
		return err
	}
	s.idx.PutBinding(binding, s.now())
	return nil
}

func (s *identitySyncer) handleIDPSession(ctx context.Context, rec *databroker.Record) error {
	if rec.GetDeletedAt() != nil {
		log.Ctx(ctx).Trace().Str("idpsession-id", rec.GetId()).Msg("deleted idpsession schedules binding revocations")
		s.idx.DeleteIDPSession(rec.GetId(), s.now())
		s.refreshManager.cleanUpSchedulers(rec.GetId())
		return nil
	}
	idpSess := &idpsession.IDPSession{}
	if err := rec.GetData().UnmarshalTo(idpSess); err != nil {
		return fmt.Errorf("incompatible idpsession record: %w", err)
	}
	if idpSess.GetUserId() == "" || idpSess.GetId() == "" {
		log.Ctx(ctx).Info().Str("record-id", rec.GetId()).Str("type-url", rec.GetData().GetTypeUrl()).Msg("invalid idpsession observed, cleaning up")
		rec.DeletedAt = timestamppb.New(s.now())
		_, err := s.clientB.GetDataBrokerServiceClient().Put(ctx, &databroker.PutRequest{Records: []*databroker.Record{rec}})
		return err
	}
	s.idx.PutIDPSession(idpSess, s.now())
	s.refreshManager.onUpdateIDPSession(ctx, idpSess)
	return nil
}
