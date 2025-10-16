package pending

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"time"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
	_ "github.com/pomerium/pomerium/pkg/ssh/pending/logger"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type distributedCodeAccessor struct {
	client databroker.DataBrokerServiceClient
}

func NewDistributedCodeAccessor(
	client databroker.DataBrokerServiceClient,
) *distributedCodeAccessor {
	return &distributedCodeAccessor{
		client: client,
	}
}

func (d *distributedCodeAccessor) GetBindingRequest(ctx context.Context, codeId CodeID) (*session.SessionBindingRequest, bool) {
	rec, err := d.client.Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.SessionBindingRequest",
		Id:   string(codeId),
	})
	if err != nil {
		return nil, false
	}
	var sess session.SessionBindingRequest
	if err := rec.Record.GetData().UnmarshalTo(&sess); err != nil {
		panic(err)
	}
	return &sess, true
}

func (d *distributedCodeAccessor) RevokeCode(ctx context.Context, codeId CodeID) error {
	slog.Default().With("codeId", codeId).Info("revoking code")
	rec, err := d.client.Get(ctx, &databroker.GetRequest{
		Type: "type.googleapis.com/session.SessionBindingRequest",
		Id:   string(codeId),
	})
	if err != nil {
		return err
	}

	if rec.Record.DeletedAt != nil {
		return nil
	}
	rec.Record.DeletedAt = timestamppb.Now()
	_, err = d.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{
			rec.Record,
		},
	})
	return err
}

type distributedCodeIssuer struct {
	client databroker.DataBrokerServiceClient
	*distributedCodeAccessor

	sbrSyncer      *sbrSyncerHandler
	identitySyncer *sessionBindingSyncerHandler

	cache *sessionCache

	done chan struct{}
	err  error
}

func NewDistributedCodeIssuer(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
) *distributedCodeIssuer {
	doneC := make(chan struct{})
	tr := NewPendingSessionTracker()
	cache := NewSessionCache()
	sbrSyncer := newSbrSyncerHandler(cache, tr, client)
	identitySyncer := newIdentitySyncerHandler(cache, tr, client)
	dci := &distributedCodeIssuer{
		done:                    doneC,
		sbrSyncer:               sbrSyncer,
		client:                  client,
		identitySyncer:          identitySyncer,
		cache:                   cache,
		distributedCodeAccessor: NewDistributedCodeAccessor(client),
	}
	eg, ctxca := errgroup.WithContext(ctx)
	eg.Go(func() error {
		syncer := databroker.NewSyncer(
			ctxca, "ssh-session-codes",
			dci.sbrSyncer,
			databroker.WithTypeURL("type.googleapis.com/session.SessionBindingRequest"),
		)
		return syncer.Run(ctxca)
	})

	eg.Go(func() error {
		syncer := databroker.NewSyncer(
			ctxca,
			"ssh-identity-syncer",
			dci.identitySyncer,
			databroker.WithTypeURL("type.googleapis.com/session.SessionBinding"),
		)
		return syncer.Run(ctxca)
	})

	go func() {
		defer close(doneC)
		dci.err = eg.Wait()
	}()

	return dci
}

var _ CodeIssuer = (*distributedCodeIssuer)(nil)

func (d *distributedCodeIssuer) IssueCode() CodeID {
	code := [16]byte{}
	rand.Read(code[:])
	codeStr := base64.RawURLEncoding.EncodeToString(code[:])
	return CodeID(codeStr)
}

func (d *distributedCodeIssuer) AssociateCode(ctx context.Context, codeId CodeID, req *session.SessionBindingRequest) (CodeID, error) {
	logger := slog.Default().With("sessionID", req.Key).With("codeId", codeId).With("action", "associate")
	// check our local cache if anything is valid...
	code, ok := d.cache.GetCode(SessionID(req.Key))
	if ok {
		// if valid
		logger.With("actualCode", code).Info("existing code found")
		return code, nil

	}
	logger.Info("no existing code found, attempting to acquire lease")
	// if not valid continue
	lease, err := d.client.AcquireLease(ctx, &databroker.AcquireLeaseRequest{
		Name:     req.Key,
		Duration: durationpb.New(time.Until(req.ExpiresAt.AsTime())),
	})
	if st, _ := status.FromError(err); st.Code() == codes.AlreadyExists {
		logger.Info("lease already acquired elsewhere")
		// continue to somerewhere else
	} else if err != nil {
		return "", err
	} else {
		logger.Info("lease acquired")
		// lease acquired
		data := protoutil.NewAny(req)
		_, err := d.client.Put(ctx, &databroker.PutRequest{
			Records: []*databroker.Record{
				{
					Id:   string(codeId),
					Type: data.GetTypeUrl(),
					Data: data,
				},
			},
		})
		if err != nil {
			return "", err
		}

		context.AfterFunc(ctx, func() {
			ctxT, ca := context.WithTimeout(context.Background(), 30*time.Second)
			defer ca()
			logger.Info("releasing lease")
			_, err := d.client.ReleaseLease(ctxT, &databroker.ReleaseLeaseRequest{
				Name: req.Key,
				Id:   lease.Id,
			})
			if err != nil {
				slog.Default().With("sessionID", req.Key, "codeId", codeId).Error("failed to release lease")
			}
		})

		return codeId, nil
	}

	t := time.NewTicker(time.Millisecond * 50)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			code, ok := d.cache.GetCode(SessionID(req.Key))
			if ok {
				logger.With("actualCode", code).Info("found code")
				return code, nil
			}
		case <-ctx.Done():
			return "", status.Error(codes.Aborted, ctx.Err().Error())
		}
	}

}

func (d *distributedCodeIssuer) OnCodeInvalid(ctx context.Context, sessionID SessionID, codeId CodeID) <-chan error {
	// TODO : this is a naive implementation
	ret := make(chan error, 1)
	go func() {
		defer close(ret)
		t := time.NewTicker(time.Millisecond * 50)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if !d.cache.IsCodeValid(sessionID, codeId) {
					ret <- fmt.Errorf("code is no longer valid")
					return
				}
			}
		}
	}()
	return ret
}
func (d *distributedCodeIssuer) OnCodeSuccess(ctx context.Context, sessionID SessionID) <-chan []*databroker.Record {
	// TODO : this is naive implementation
	ret := make(chan []*databroker.Record, 1)
	go func() {
		defer close(ret)
		t := time.NewTicker(time.Millisecond * 50)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				recs, ok := d.cache.GetSession(sessionID)
				if ok {
					ret <- recs
					return
				}
			}
		}
	}()
	return ret
}
func (d *distributedCodeIssuer) Done() chan struct{} {
	return d.done
}
