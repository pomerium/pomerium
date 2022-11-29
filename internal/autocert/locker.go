package autocert

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/internal/atomicutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
)

const (
	leaseDuration      = time.Minute
	leaseRenewInterval = leaseDuration / 4
)

type dataBrokerLocker struct {
	name        string
	client      *atomicutil.Value[databroker.DataBrokerServiceClient]
	localLocker *channelLocker
	id          string

	renewCtx    context.Context
	renewCancel context.CancelFunc
}

func newDataBrokerLocker(name string, client *atomicutil.Value[databroker.DataBrokerServiceClient]) *dataBrokerLocker {
	return &dataBrokerLocker{
		name:        name,
		client:      client,
		localLocker: newChannelLocker(),
		renewCancel: func() {},
	}
}

func (locker *dataBrokerLocker) Lock(ctx context.Context) error {
	// acquire the local lock
	if err := locker.localLocker.Lock(ctx); err != nil {
		return err
	}
	defer locker.localLocker.Unlock()

	for {
		// attempt to acquire the lease
		res, err := locker.client.Load().AcquireLease(ctx, &databroker.AcquireLeaseRequest{
			Name:     locker.name,
			Duration: durationpb.New(leaseDuration),
		})

		// if the lease is already taken, wait and retry
		if status.Code(err) == codes.AlreadyExists {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}

		// any other error is unexpected, so return it
		if err != nil {
			return err
		}

		// start a background goroutine to renew the lease periodically
		locker.renewCtx, locker.renewCancel = context.WithCancel(context.Background())
		go locker.periodicallyRenewLease(locker.renewCtx, res.GetId())

		// store the id for later release
		locker.id = res.GetId()

		return nil
	}
}

func (locker *dataBrokerLocker) Unlock(ctx context.Context) error {
	// acquire the local lock
	if err := locker.localLocker.Lock(ctx); err != nil {
		return err
	}
	defer locker.localLocker.Unlock()

	// cancel the lease renewal loop
	locker.renewCancel()

	// release the lease
	_, err := locker.client.Load().ReleaseLease(ctx, &databroker.ReleaseLeaseRequest{
		Name: locker.name,
		Id:   locker.id,
	})
	if err != nil {
		return err
	}
	return nil
}

func (locker *dataBrokerLocker) periodicallyRenewLease(ctx context.Context, id string) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(leaseRenewInterval):
		}

		_, _ = locker.client.Load().RenewLease(ctx, &databroker.RenewLeaseRequest{
			Name: locker.name,
			Id:   id,
		})
	}
}

type channelLocker struct {
	ch chan struct{}
}

func newChannelLocker() *channelLocker {
	return &channelLocker{ch: make(chan struct{}, 1)}
}

func (locker *channelLocker) Lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case locker.ch <- struct{}{}:
		return nil
	}
}

func (locker *channelLocker) Unlock() {
	select {
	case <-locker.ch:
	default:
	}
}
