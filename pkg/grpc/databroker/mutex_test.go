package databroker_test

import (
	"context"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/trace/noop"
	grpc "google.golang.org/grpc"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestMutex(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		ctx := t.Context()

		backend := databroker.NewBackendServer(noop.NewTracerProvider())
		t.Cleanup(backend.Stop)
		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			databrokerpb.RegisterDataBrokerServiceServer(s, backend)
		})
		client := databrokerpb.NewDataBrokerServiceClient(cc)

		mu := databrokerpb.NewMutex(client, "example", 10*time.Second)

		var wg1 sync.WaitGroup
		taken := make(chan struct{})
		wg1.Add(1)
		go func() {
			defer wg1.Done()
			err := mu.TryLockAndRun(ctx, func(_ context.Context) error {
				close(taken)
				time.Sleep(time.Second)
				return nil
			})
			assert.NoError(t, err)
		}()
		<-taken
		wg1.Add(1)
		go func() {
			defer wg1.Done()
			err := mu.TryLockAndRun(ctx, func(_ context.Context) error { return nil })
			assert.Error(t, err, "should return an error because the lock is held")
		}()
		wg1.Add(1)
		go func() {
			defer wg1.Done()
			err := mu.LockAndRun(ctx, func(_ context.Context) error { return nil })
			assert.NoError(t, err, "should wait until the lock is released")
		}()
		wg1.Wait()

		// test renewal
		var wg2 sync.WaitGroup
		taken = make(chan struct{})
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			err := mu.LockAndRun(ctx, func(_ context.Context) error {
				close(taken)
				time.Sleep(time.Minute)
				return nil
			})
			assert.NoError(t, err, "should renew lease")
		}()
		<-taken
		wg2.Add(1)
		go func() {
			defer wg2.Done()
			time.Sleep(time.Second * 30)
			err := mu.TryLockAndRun(ctx, func(_ context.Context) error { return nil })
			assert.Error(t, err, "should return an error because the lock is still held")
		}()
		wg2.Wait()
	})
}
