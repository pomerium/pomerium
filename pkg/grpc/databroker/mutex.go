package databroker

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
)

// A Mutex implements a distributed mutual exclusion lock using leases.
type Mutex struct {
	client    DataBrokerServiceClient
	leaseName string
	ttl       time.Duration
}

// NewMutex creates a new Mutex.
func NewMutex(client DataBrokerServiceClient, name string, ttl time.Duration) *Mutex {
	return &Mutex{
		client:    client,
		leaseName: fmt.Sprintf("mutex-%s", name),
		ttl:       ttl,
	}
}

// LockAndRun acquires the lock and runs the critical section. If the lock is already held it will
// block until it can acquire the lock or ctx is canceled.
func (mu *Mutex) LockAndRun(ctx context.Context, criticalSection func(ctx context.Context) error) error {
	ticker := time.NewTicker(mu.ttl / 2)
	defer ticker.Stop()

	var leaseID string
	for {
		res, err := mu.client.AcquireLease(ctx, &AcquireLeaseRequest{
			Name:     mu.leaseName,
			Duration: durationpb.New(mu.ttl),
		})
		if err == nil {
			leaseID = res.Id
			break
		} else if status.Code(err) != codes.AlreadyExists {
			return err
		}

		// the lease is already taken, so we will wait and try again
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-ticker.C:
		}
	}

	return mu.runWithLease(ctx, leaseID, criticalSection)
}

// TryLockAndRun attempts to acquire the lock and run the critical section. If the lock is already held
// an error will be returned.
func (mu *Mutex) TryLockAndRun(ctx context.Context, criticalSection func(ctx context.Context) error) error {
	res, err := mu.client.AcquireLease(ctx, &AcquireLeaseRequest{
		Name:     mu.leaseName,
		Duration: durationpb.New(mu.ttl),
	})
	if err != nil {
		return err
	}

	return mu.runWithLease(ctx, res.Id, criticalSection)
}

func (mu *Mutex) runWithLease(ctx context.Context, leaseID string, criticalSection func(ctx context.Context) error) error {
	// make sure to release the lease after we're done
	defer func() {
		_, _ = mu.client.ReleaseLease(ctx, &ReleaseLeaseRequest{
			Name: mu.leaseName,
			Id:   leaseID,
		})
	}()

	// create a new cancelable context that the critical section can use to detect if the lease is lost
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(context.Canceled)

	// periodically renew the lease
	go func() {
		ticker := time.NewTicker(mu.ttl / 2)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}

			_, err := mu.client.RenewLease(ctx, &RenewLeaseRequest{
				Name:     mu.leaseName,
				Id:       leaseID,
				Duration: durationpb.New(mu.ttl),
			})
			if err != nil {
				cancel(err)
				return
			}
		}
	}()

	return criticalSection(ctx)
}
