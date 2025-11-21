package code

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/cenkalti/backoff/v4"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type issuer struct {
	done chan struct{}

	mgr *codeManager
	Reader
	Revoker

	clientB databroker.ClientGetter
}

func NewIssuer(ctx context.Context, client databroker.ClientGetter) Issuer {
	doneC := make(chan struct{})
	initVal := &atomic.Uint32{}
	initVal.Store(0)
	i := &issuer{
		clientB: client,
		done:    doneC,
		mgr:     newCodeManager(client),
		Reader:  NewReader(client),
		Revoker: NewRevoker(client),
	}

	eg, ctxca := errgroup.WithContext(ctx)

	eg.Go(func() error {
		syncer := databroker.NewSyncer(
			ctxca,
			"session-biding-request-mgr",
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

func (i *issuer) AssociateCode(
	ctx context.Context,
	code CodeID,
	sbr *session.SessionBindingRequest,
) (CodeID, error) {
	b := backoff.WithContext(backoff.NewExponentialBackOff(), ctx)
	maybeCode, err := backoff.RetryWithData(func() (CodeID, error) {
		maybeCode, err := getCodeByBindingKey(ctx, i.clientB.GetDataBrokerServiceClient(), sbr.Key)
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			return "", nil
		}
		return maybeCode, nil
	}, b)
	if err != nil {
		return "", err
	}
	if maybeCode == "" {
		if _, err := i.clientB.GetDataBrokerServiceClient().Put(ctx, &databroker.PutRequest{
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
		maybeCode, err := getCodeByBindingKey(ctx, i.clientB.GetDataBrokerServiceClient(), sbr.Key)
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
