package code

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type issuer struct {
	client databroker.DataBrokerServiceClient
	done   chan struct{}

	setupDone *atomic.Uint32
	setupF    *sync.Once
	// CodeAcessor

	mgr *codeManager
	Reader
	Revoker
}

func NewIssuer(ctx context.Context, client databroker.DataBrokerServiceClient) Issuer {
	doneC := make(chan struct{})
	initVal := &atomic.Uint32{}
	initVal.Store(0)
	i := &issuer{
		client:    client,
		done:      doneC,
		setupDone: initVal,
		setupF:    &sync.Once{},
		mgr:       newCodeManager(client),
		Reader:    NewReader(client),
		Revoker:   NewRevoker(client),
	}

	eg, ctxca := errgroup.WithContext(ctx)

	log.Ctx(ctx).Info().Msg("Agocs: doing the thing 2")
	eg.Go(func() error {
		syncer := databroker.NewSyncer(
			ctx,
			"session-binding-request-mgr",
			i.mgr,
			databroker.WithTypeURL("type.googleapis.com/session.SessionBindingRequest"),
		)
		return syncer.Run(ctxca)
	})
	go func() {
		defer close(i.done)
		_ = eg.Wait()
	}()
	return i
}

var _ Issuer = (*issuer)(nil)

func (i *issuer) waitForSetup() error {
	// FIXME: this needs to run once everywhere we query SessionBindingRequest and SessionBinding's
	// we want to avoid sharing a sync.Once for coordination across packages, and run this only once
	// per pomerium instance.
	i.setupF.Do(func() {
		ctxT, ca := context.WithTimeout(context.Background(), 5*time.Minute)
		defer ca()
		if err := i.setup(ctxT); err != nil {
			panic(err)
		}
	})

	if i.setupDone.Load() == 0 {
		return fmt.Errorf("not yet initialized")
	}
	return nil
}

func (i *issuer) IssueCode() CodeID {
	code := [16]byte{}
	_, _ = rand.Read(code[:])
	codeStr := base64.RawURLEncoding.EncodeToString(code[:])
	return CodeID(codeStr)
}

func (i *issuer) OnCodeDecision(ctx context.Context, code CodeID) <-chan Status {
	ret := make(chan Status, 1)

	go func() {
		defer close(ret)
		t := time.NewTicker(time.Millisecond * 150)
		defer t.Stop()
		id := string(code)

		for {
		RETRY:
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				st, ok := i.mgr.GetByCodeID(id)
				if !ok {
					goto RETRY
				}
				if st.ExpiresAt.Before(time.Now()) {
					return
				}
				if st.State != session.SessionBindingRequestState_InFlight {
					ret <- st
					return
				}
			}
		}
	}()
	return ret
}

func (i *issuer) setup(ctx context.Context) error {
	reqCap := uint64(50000)

	b := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)
	if err := backoff.Retry(func() error {
		_, err := i.client.SetOptions(ctx, &databroker.SetOptionsRequest{
			Type: "type.googleapis.com/session.SessionBindingRequest",
			Options: &databroker.Options{
				Capacity:        &reqCap,
				IndexableFields: []string{"key"},
			},
		})
		return err
	}, b); err != nil {
		return err
	}

	if err := backoff.Retry(func() error {
		_, err := i.client.SetOptions(ctx, &databroker.SetOptionsRequest{
			Type: "type.googleapis.com/session.SessionBinding",
			Options: &databroker.Options{
				IndexableFields: []string{
					"session_id",
					"user_id",
				},
			},
		})
		return err
	}, b); err != nil {
		return err
	}

	if err := backoff.Retry(func() error {
		_, err := i.client.SetOptions(ctx, &databroker.SetOptionsRequest{
			Type: "type.googleapis.com/session.IdentityBinding",
			Options: &databroker.Options{
				IndexableFields: []string{
					"user_id",
				},
			},
		})
		return err
	}, b); err != nil {
		return err
	}
	i.setupDone.CompareAndSwap(0, 1)
	return nil
}

func (i *issuer) AssociateCode(
	ctx context.Context,
	code CodeID,
	sbr *session.SessionBindingRequest,
) (CodeID, error) {
	if err := i.waitForSetup(); err != nil {
		return "", err
	}
	b := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)
	maybeCode, err := backoff.RetryWithData(func() (CodeID, error) {
		maybeCode, err := getCodeByBindingKey(ctx, i.client, sbr.Key)
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return "", nil
		}
		return maybeCode, nil
	}, b)
	if err != nil {
		return "", err
	}
	if maybeCode == "" {
		if _, err := i.client.Put(ctx, &databroker.PutRequest{
			Records: []*databroker.Record{
				{
					Type: grpcutil.GetTypeURL(sbr),
					Id:   string(code),
					Data: protoutil.NewAny(sbr),
				},
			},
		}); err != nil {
			return "", err
		}
	}
	maybeCode, err = backoff.RetryWithData(func() (CodeID, error) {
		maybeCode, err := getCodeByBindingKey(ctx, i.client, sbr.Key)
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return "", nil
		}
		if err != nil {
			return "", err
		}
		if maybeCode == "" {
			return "", fmt.Errorf("failed to resolve code")
		}
		return maybeCode, nil
	}, b)
	if err != nil {
		return "", err
	}
	return maybeCode, nil
}

func (i *issuer) Done() chan struct{} {
	return i.done
}
