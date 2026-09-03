package idpsession

import (
	"context"
	"fmt"
	"time"

	"github.com/pomerium/pomerium/internal/events"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/idpsession"
	"github.com/pomerium/pomerium/pkg/identity"
	"go.opentelemetry.io/otel/trace/noop"
)

type idpSessionSyncer struct {
	clientB   databroker.ClientGetter
	dataStore *dataStore
	notifier  SyncNotifier

	refreshManager *refreshManager
}

func newIdpSessionSyncer(
	clientB databroker.ClientGetter,
	dataStore *dataStore,
	notifier SyncNotifier,
) *idpSessionSyncer {
	// TODO : hardcoded
	cfg := config{
		sessionRefreshGracePeriod:     1 * time.Minute,
		sessionRefreshCoolOffDuration: 10 * time.Second,
		updateUserInfoInterval:        10 * time.Minute,
		// config.RuntimeFlagRefreshSessionAtIDTokenExpiration]
		refreshSessionAtIDTokenExpiration: true,
		tracerProvider:                    noop.TracerProvider{},
		now: func() time.Time {
			return time.Now()
		},
		eventMgr: events.New(),
		getAuthenticator: func(ctx context.Context, idpID string) (identity.Authenticator, error) {
			panic("get me from config")
		},
	}
	return &idpSessionSyncer{
		clientB:        clientB,
		dataStore:      dataStore,
		notifier:       notifier,
		refreshManager: newRefreshManager(cfg, dataStore, clientB),
	}
}

var _ databrokerutil.SyncerHandler = (*idpSessionSyncer)(nil)

var _ databrokerutil.SyncerHandler = (*bindingSyncer)(nil)

func (s *idpSessionSyncer) Run(ctx context.Context) error {
	syncer := databrokerutil.NewSyncer(
		ctx,
		"idpsession--syncer",
		s,
		databrokerutil.WithFastForward(),
		databrokerutil.WithTypeURL("type.googleapis.com/idpsession.IDPSession"),
	)
	return syncer.Run(ctx)
}

func (s *idpSessionSyncer) GetDataBrokerServiceClient() databroker.DataBrokerServiceClient {
	return s.clientB.GetDataBrokerServiceClient()
}

func (s *idpSessionSyncer) ClearRecords(ctx context.Context) {
	// before clearing notify.
	s.notifier.Reset()
	s.dataStore.deleteAllIDPSessions()
}

func (s *idpSessionSyncer) UpdateRecords(ctx context.Context, serverVersion uint64, recs []*databroker.Record) {
	for _, rec := range recs {
		if err := s.handleIDPSession(ctx, rec); err != nil {
			log.Ctx(ctx).Err(err).Msg("failed to handle idpsession update")
			continue
		}
	}
	s.notifier.Updated()
}

func (s *idpSessionSyncer) handleIDPSession(ctx context.Context, rec *databroker.Record) error {
	if rec.GetDeletedAt() != nil {
		s.dataStore.deleteIDPSession(rec.GetId())
		// TODO : on delete remember to never delete user.User in the reconciler
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
