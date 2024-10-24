package databroker_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
)

func TestLeaser(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	exitErr := errors.New("EXIT")

	t.Run("acquires lease", func(t *testing.T) {
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().
			AcquireLease(gomock.Any(), &databroker.AcquireLeaseRequest{
				Name:     "TEST",
				Duration: durationpb.New(time.Second * 30),
			}).
			Return(&databroker.AcquireLeaseResponse{
				Id: "lease1",
			}, nil).
			Times(1)
		client.EXPECT().
			ReleaseLease(gomock.Any(), &databroker.ReleaseLeaseRequest{
				Name: "TEST",
				Id:   "lease1",
			}).
			Times(1)

		handler := mock_databroker.NewMockLeaserHandler(ctrl)
		handler.EXPECT().
			GetDataBrokerServiceClient().
			Return(client).
			AnyTimes()
		handler.EXPECT().
			RunLeased(gomock.Any()).
			Return(exitErr).
			Times(1)

		leaser := databroker.NewLeaser("TEST", time.Second*30, handler)
		err := leaser.Run(context.Background())
		assert.Equal(t, exitErr, err)
	})
	t.Run("retries acquire", func(t *testing.T) {
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().
			AcquireLease(gomock.Any(), &databroker.AcquireLeaseRequest{
				Name:     "TEST",
				Duration: durationpb.New(time.Second * 30),
			}).
			Return(nil, status.Error(codes.Unavailable, "UNAVAILABLE")).
			Times(2)
		client.EXPECT().
			AcquireLease(gomock.Any(), &databroker.AcquireLeaseRequest{
				Name:     "TEST",
				Duration: durationpb.New(time.Second * 30),
			}).
			Return(&databroker.AcquireLeaseResponse{
				Id: "lease1",
			}, nil).
			Times(1)
		client.EXPECT().
			ReleaseLease(gomock.Any(), &databroker.ReleaseLeaseRequest{
				Name: "TEST",
				Id:   "lease1",
			}).
			Times(1)

		handler := mock_databroker.NewMockLeaserHandler(ctrl)
		handler.EXPECT().
			GetDataBrokerServiceClient().
			Return(client).
			AnyTimes()
		handler.EXPECT().
			RunLeased(gomock.Any()).
			Return(exitErr).
			Times(1)

		leaser := databroker.NewLeaser("TEST", time.Second*30, handler)
		err := leaser.Run(context.Background())
		assert.Equal(t, exitErr, err)
	})
	t.Run("renews", func(t *testing.T) {
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().
			AcquireLease(gomock.Any(), &databroker.AcquireLeaseRequest{
				Name:     "TEST",
				Duration: durationpb.New(time.Millisecond),
			}).
			Return(&databroker.AcquireLeaseResponse{
				Id: "lease1",
			}, nil).
			Times(1)
		client.EXPECT().
			RenewLease(gomock.Any(), &databroker.RenewLeaseRequest{
				Name:     "TEST",
				Id:       "lease1",
				Duration: durationpb.New(time.Millisecond),
			}).
			MinTimes(1)
		client.EXPECT().
			ReleaseLease(gomock.Any(), &databroker.ReleaseLeaseRequest{
				Name: "TEST",
				Id:   "lease1",
			}).
			Times(1)

		handler := mock_databroker.NewMockLeaserHandler(ctrl)
		handler.EXPECT().
			GetDataBrokerServiceClient().
			Return(client).
			AnyTimes()
		handler.EXPECT().
			RunLeased(gomock.Any()).
			DoAndReturn(func(_ context.Context) error {
				time.Sleep(time.Millisecond * 20)
				return exitErr
			}).
			Times(1)

		leaser := databroker.NewLeaser("TEST", time.Millisecond, handler)
		err := leaser.Run(context.Background())
		assert.Equal(t, exitErr, err)
	})
}

func TestLeasers(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	exitErr := errors.New("EXIT")

	client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	client.EXPECT().
		AcquireLease(gomock.Any(), &databroker.AcquireLeaseRequest{
			Name:     "TEST",
			Duration: durationpb.New(time.Second * 30),
		}).
		Return(&databroker.AcquireLeaseResponse{
			Id: "lease1",
		}, nil).
		Times(1)
	client.EXPECT().
		ReleaseLease(gomock.Any(), &databroker.ReleaseLeaseRequest{
			Name: "TEST",
			Id:   "lease1",
		}).
		Times(1)

	var counter int64
	fn1 := func(_ context.Context) error {
		atomic.AddInt64(&counter, 1)
		return exitErr
	}
	fn2 := func(ctx context.Context) error {
		atomic.AddInt64(&counter, 10)
		<-ctx.Done()
		return context.Cause(ctx)
	}
	leaser := databroker.NewLeasers("TEST", time.Second*30, client, fn1, fn2)
	err := leaser.Run(context.Background())
	assert.Equal(t, exitErr, err)
	assert.EqualValues(t, 11, counter)
}
