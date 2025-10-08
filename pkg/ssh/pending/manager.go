package pending

import (
	"context"
	"fmt"
	"time"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

type PendingSessionManager struct {
	client databroker.DataBrokerServiceClient

	done chan struct{}
	err  error

	tr *pendingSessionTracker
	eg *errgroup.Group
	// waiters sync.Map

	seenVersion uint64

	sbrHandler *sbrSyncerHandler
	sbHandler  *sessionBindingSyncerHandler
}

var _ Tracker = (*PendingSessionManager)(nil)

func NewPendingSessionManager(ctx context.Context, client databroker.DataBrokerServiceClient) *PendingSessionManager {
	mgr := &PendingSessionManager{
		client: client,
		done:   make(chan struct{}),
		tr:     NewPendingSessionTracker(),
		eg:     &errgroup.Group{},
	}
	cache := NewSessionCache()
	mgr.sbrHandler = newSbrSyncerHandler(cache, mgr.tr, mgr.client)
	mgr.sbHandler = &sessionBindingSyncerHandler{
		tr:     mgr.tr,
		client: mgr.client,
	}
	mgr.eg.Go(func() error {
		return mgr.runSessionBindingReqSync(ctx)
	})

	mgr.eg.Go(func() error {
		return mgr.runSessionBindingSync(ctx)
	})

	go func() {
		defer close(mgr.done)
		mgr.err = mgr.eg.Wait()
	}()

	return mgr
}

func (mgr *PendingSessionManager) Inc(sessionID string) {
	mgr.tr.Inc(sessionID)
}

func (mgr *PendingSessionManager) Dec(sessionID string) {
	mgr.tr.Dec(sessionID)
}

func (mgr *PendingSessionManager) GetRecords(sessionID string) (<-chan []*databroker.Record, bool) {
	return mgr.tr.GetRecords(sessionID)
}

func (mgr *PendingSessionManager) GetBindingRequest(sessionID string) (<-chan *SessionBindingCode, bool) {
	return mgr.tr.GetBindingRequest(sessionID)
}

func (mgr *PendingSessionManager) WatchBindingRequest(sessionID string) (<-chan *SessionBindingCode, bool) {
	return mgr.tr.GetBindingRequest(sessionID)
}

func (mgr *PendingSessionManager) runSessionBindingSync(ctx context.Context) error {
	syncer := databroker.NewSyncer(ctx, "session-binding-mgr", mgr.sbHandler, databroker.WithTypeURL("type.googleapis.com/session.SessionBinding"))
	return syncer.Run(ctx)
}

func (mgr *PendingSessionManager) runSessionBindingReqSync(ctx context.Context) error {
	syncer := databroker.NewSyncer(ctx, "session-binding-req-mgr", mgr.sbrHandler, databroker.WithTypeURL("type.googleapis.com/session.SessionBindingRequest"))
	return syncer.Run(ctx)
}

func (mgr *PendingSessionManager) getSeenVersion() uint64 {
	return mgr.sbrHandler.getSeenVersion()
}

func (mgr *PendingSessionManager) persistCode(
	ctx context.Context,
	userCode string,
	sessionRequest *session.SessionBindingRequest,
) (err error) {
	data := protoutil.NewAny(sessionRequest)
	pr, err := mgr.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: data.GetTypeUrl(),
			Id:   userCode,
			Data: data,
		}},
	})
	fmt.Println(pr)
	return err
}

func (mgr *PendingSessionManager) checkVersions(ctx context.Context, version uint64) error {
	t := time.NewTicker(time.Millisecond * 100)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if mgr.getSeenVersion() == version {
				return nil
			}
		}
	}
}

func (mgr *PendingSessionManager) Start(
	ctx context.Context,
	userCode string,
	sessionRequest *session.SessionBindingRequest,
) (*session.SessionBindingRequest, error) {
RETRY:
	data := protoutil.NewAny(sessionRequest)
	var retSessionBindingRequest session.SessionBindingRequest
	isValid := true
	resp, err := mgr.client.Get(ctx, &databroker.GetRequest{
		Type: data.GetTypeUrl(),
		Id:   sessionRequest.Key,
	})
	if resp != nil {
		if err := resp.GetRecord().GetData().UnmarshalTo(&retSessionBindingRequest); err != nil {
			panic(err)
		}
		if retSessionBindingRequest.ExpiresAt.AsTime().Before(time.Now()) || resp.GetRecord().DeletedAt != nil {
			isValid = false
		}
	}

	if (err != nil && storage.IsNotFound(err)) || !isValid {
		leaseResp, err := mgr.client.AcquireLease(ctx, &databroker.AcquireLeaseRequest{
			Name:     "",
			Duration: durationpb.New(time.Until(sessionRequest.ExpiresAt.AsTime())),
		})
		if st, ok := status.FromError(err); ok && st.Code() == codes.AlreadyExists {
			goto RETRY
		}

		// we have acquired the lease!
		// please release it eventually...
		context.AfterFunc(ctx, func() {
			ctxT, ca := context.WithTimeout(context.Background(), time.Second*30)
			defer ca()
			mgr.client.ReleaseLease(ctxT, &databroker.ReleaseLeaseRequest{
				Name: sessionRequest.Key,
				Id:   leaseResp.Id,
			})
		})
		log.Info().Msg("decided to put it here")
		_, err = mgr.client.Put(ctx, &databroker.PutRequest{
			Records: []*databroker.Record{
				{
					Id:      sessionRequest.Key,
					Version: 0,
					Type:    data.GetTypeUrl(),
					Data:    data,
				},
			},
		})
		if err != nil {
			log.Info().Msg("")
			goto RETRY
		}
		goto RETRY

	} else if err != nil {
		return nil, err
	}
	var existingSbr session.SessionBindingRequest
	if err := resp.GetRecord().GetData().UnmarshalTo(&existingSbr); err != nil {
		panic(err)
	}
	return &existingSbr, nil
}

func (mgr *PendingSessionManager) Start2(
	ctx context.Context,
	userCode string,
	sessionRequest *session.SessionBindingRequest,
) (
	sbr *SessionBindingCode,
	err error,

) {
	// TODO : get version from remote
	version := mgr.getSeenVersion()

	// Check until probably synced
	if err := mgr.checkVersions(ctx, version); err != nil {
		return nil, err
	}

	// Try to get a code...
	codeBindingC, ok := mgr.tr.GetBindingRequest(sessionRequest.Key)
	if !ok {
		panic("its gonna be ok...")
	}
	select {
	case existingCode := <-codeBindingC:
		return existingCode, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(time.Millisecond * 50):
	}

	// == Persist a new code if none are found
	if err := mgr.persistCode(ctx, userCode, sessionRequest); err != nil {
		return nil, err
	}

	newCodeBindingC, ok := mgr.tr.GetBindingRequest(sessionRequest.Key)
	if !ok {
		panic("this should always exist")
	}

	select {
	case existingCode := <-newCodeBindingC:
		return existingCode, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (mgr *PendingSessionManager) Done() <-chan struct{} {
	return mgr.done
}

// Err() is guaranteed to return a non-nil error after Done() is closed.
func (mgr *PendingSessionManager) Err() error {
	select {
	case <-mgr.done:
		if mgr.err == nil {
			panic("bug: error must not be nil")
		}
	default:
		panic("bug: Err() called before Done() channel closed")
	}
	return mgr.err
}
