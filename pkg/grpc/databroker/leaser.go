package databroker

import (
	"context"
	"errors"
	"time"

	"github.com/cenkalti/backoff/v4"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/internal/log"
)

// a retryableError is one we'll retry later
type retryableError struct {
	error
}

func (err retryableError) Is(target error) bool {
	if _, ok := target.(retryableError); ok {
		return true
	}
	return false
}

// A LeaserHandler is a handler for the locker.
type LeaserHandler interface {
	GetDataBrokerServiceClient() DataBrokerServiceClient
	RunLeased(ctx context.Context) error
}

// A Leaser attempts to acquire a lease and if successful runs the handler. If the lease
// is released the context used for the handler will be canceled and a new lease
// acquisition will be attempted.
type Leaser struct {
	handler   LeaserHandler
	leaseName string
	ttl       time.Duration
}

// NewLeaser creates a new Leaser.
func NewLeaser(leaseName string, ttl time.Duration, handler LeaserHandler) *Leaser {
	return &Leaser{
		leaseName: leaseName,
		ttl:       ttl,
		handler:   handler,
	}
}

// Run acquires the lease and runs the handler. This continues until either:
//
// 1. ctx is canceled
// 2. a non-cancel error is returned from handler
//
func (locker *Leaser) Run(ctx context.Context) error {
	retryTicker := time.NewTicker(locker.ttl / 2)
	defer retryTicker.Stop()

	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 0
	for {
		err := locker.runOnce(ctx, bo.Reset)
		switch {
		case err == nil:
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-retryTicker.C:
			}
		case errors.Is(err, retryableError{}):
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(bo.NextBackOff()):
			}
		default:
			return err
		}
	}
}

func (locker *Leaser) runOnce(ctx context.Context, resetBackoff func()) error {
	res, err := locker.handler.GetDataBrokerServiceClient().AcquireLease(ctx, &AcquireLeaseRequest{
		Name:     locker.leaseName,
		Duration: durationpb.New(locker.ttl),
	})
	// if the lease already exists, retry later
	if status.Code(err) == codes.AlreadyExists {
		return nil
	} else if err != nil {
		log.Warn(ctx).Err(err).Msg("leaser: error acquiring lease")
		return retryableError{err}
	}
	resetBackoff()
	leaseID := res.Id

	log.Debug(ctx).
		Str("lease_name", locker.leaseName).
		Str("lease_id", leaseID).
		Msg("leaser: lease acquired")

	return locker.withLease(ctx, leaseID)
}

func (locker *Leaser) withLease(ctx context.Context, leaseID string) error {
	// always release the lock in case the parent context is canceled
	defer func() {
		_, _ = locker.handler.GetDataBrokerServiceClient().ReleaseLease(context.Background(), &ReleaseLeaseRequest{
			Name: locker.leaseName,
			Id:   leaseID,
		})
	}()

	renewTicker := time.NewTicker(locker.ttl / 2)
	defer renewTicker.Stop()

	// if renewal fails, cancel the handler
	runCtx, runCancel := context.WithCancel(ctx)
	eg, egCtx := errgroup.WithContext(runCtx)
	eg.Go(func() error {
		defer runCancel()

		for {
			select {
			case <-egCtx.Done():
				return egCtx.Err()
			case <-renewTicker.C:
			}

			_, err := locker.handler.GetDataBrokerServiceClient().RenewLease(ctx, &RenewLeaseRequest{
				Name:     locker.leaseName,
				Id:       leaseID,
				Duration: durationpb.New(locker.ttl),
			})
			if status.Code(err) == codes.AlreadyExists {
				log.Debug(ctx).
					Str("lease_name", locker.leaseName).
					Str("lease_id", leaseID).
					Msg("leaser: lease lost")
				// failed to renew lease
				return nil
			} else if err != nil {
				log.Warn(ctx).Err(err).Msg("leaser: error renewing lease")
				return retryableError{err}
			}
		}
	})
	eg.Go(func() error {
		return locker.handler.RunLeased(egCtx)
	})
	err := eg.Wait()
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}
