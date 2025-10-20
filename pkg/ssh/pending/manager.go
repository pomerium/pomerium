package pending

import (
	"context"
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

	eg *errgroup.Group
	// waiters sync.Map

	sbrHandler *sbrSyncerHandler
	sbHandler  *sessionBindingSyncerHandler
}

func NewPendingSessionManager(ctx context.Context, client databroker.DataBrokerServiceClient) *PendingSessionManager {
	mgr := &PendingSessionManager{
		client: client,
		done:   make(chan struct{}),
		eg:     &errgroup.Group{},
	}
	cache := NewSessionCache()
	mgr.sbrHandler = newSbrSyncerHandler(cache, mgr.client)
	mgr.sbHandler = &sessionBindingSyncerHandler{
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

func (mgr *PendingSessionManager) runSessionBindingSync(ctx context.Context) error {
	syncer := databroker.NewSyncer(ctx, "session-binding-mgr", mgr.sbHandler, databroker.WithTypeURL("type.googleapis.com/session.SessionBinding"))
	return syncer.Run(ctx)
}

func (mgr *PendingSessionManager) runSessionBindingReqSync(ctx context.Context) error {
	syncer := databroker.NewSyncer(ctx, "session-binding-req-mgr", mgr.sbrHandler, databroker.WithTypeURL("type.googleapis.com/session.SessionBindingRequest"))
	return syncer.Run(ctx)
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
