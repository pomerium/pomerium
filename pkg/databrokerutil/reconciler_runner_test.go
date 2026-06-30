package databrokerutil

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"testing/synctest"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/mock/gomock"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
)

func TestReconcilerRunner(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// Set up a mock reconciler that allows us to control when a reconcile
		// operation finishes.
		var calls int
		reconcileCh := make(chan struct{})
		r := &mockReconciler{
			reconcile: func(context.Context) error {
				calls++
				<-reconcileCh
				return nil
			},
		}
		finishReconcile := func() { reconcileCh <- struct{}{} }

		rr := NewReconcilerRunner(r, "test", nil)

		ctx, cancel := context.WithCancel(t.Context())

		var runError error

		go func() { runError = rr.(*reconcilerRunner).RunLeased(ctx) }()
		synctest.Wait()
		assert.Equal(t, 1, calls,
			"Reconcile should be called immediately, even before the first trigger")
		finishReconcile()

		rr.TriggerSync()
		synctest.Wait()
		assert.Equal(t, 2, calls, "Reconcile should be called again after a trigger")
		finishReconcile()

		rr.TriggerSync()
		rr.TriggerSync()
		synctest.Wait()
		assert.Equal(t, 3, calls,
			"multiple triggers in rapid succession should coalesce into one Reconcile call")
		finishReconcile()

		cancel()
		synctest.Wait()
		assert.Equal(t, 3, calls,
			"Reconcile should not be called again after context cancellation")
		assert.ErrorIs(t, runError, context.Canceled)
	})
}

func TestReconcilerRunnerErrorLogging(t *testing.T) {
	t.Parallel()

	synctest.Test(t, func(t *testing.T) {
		// Set up a mock reconciler that always returns an error.
		var calls int
		r := &mockReconciler{
			reconcile: func(_ context.Context) error {
				calls++
				return fmt.Errorf("reconcile error #%d", calls)
			},
		}

		rr := NewReconcilerRunner(r, "test", nil)

		// Capture log output to a buffer.
		var logBuf bytes.Buffer
		logger := zerolog.New(&logBuf)
		ctx, cancel := context.WithCancel(logger.WithContext(t.Context()))

		var runError error

		go func() { runError = rr.(*reconcilerRunner).RunLeased(ctx) }()
		synctest.Wait()

		// The first reconcile error should be logged.
		assert.JSONEq(t, `{
			"level": "error",
			"service": "test-reconciler",
			"error": "reconcile error #1",
			"message": "reconcile"
		}`, logBuf.String())

		// Trigger another reconcile to verify the loop continues after an error.
		// The next reconcile error should be logged.
		logBuf.Reset()
		rr.TriggerSync()
		synctest.Wait()
		assert.JSONEq(t, `{
			"level": "error",
			"service": "test-reconciler",
			"error": "reconcile error #2",
			"message": "reconcile"
		}`, logBuf.String())

		// These reconcile errors should not propagate to the value returned by
		// the ReconcilerRunner.RunLeased() method.
		cancel()
		synctest.Wait()
		assert.ErrorIs(t, runError, context.Canceled)
	})
}

func TestReconcilerRunnerClientGetter(t *testing.T) {
	t.Parallel()

	var client databroker.DataBrokerServiceClient
	clientGetter := databroker.ClientGetterFunc(func() databroker.DataBrokerServiceClient { return client })
	rr := NewReconcilerRunner(nil, "test", clientGetter)

	ctrl := gomock.NewController(t)
	client1 := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
	client2 := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

	// GetDataBrokerServiceClient() should always return the latest client.
	client = client1
	assert.Equal(t, client1, rr.GetDataBrokerServiceClient())

	client = client2
	assert.Equal(t, client2, rr.GetDataBrokerServiceClient())
}

func TestReconcilerRunnerOptionsSet(t *testing.T) {
	t.Parallel()

	attr := attribute.String("test", "value")
	interval := 123 * time.Second
	traceProvider := noop.NewTracerProvider()

	r := NewReconcilerRunner(nil, "lease-name", nil,
		WithAttributes(attr),
		WithInterval(interval),
		WithReconcilerErrorHandler(func(error) {}),
		WithReconcilerTracerProvider(traceProvider),
	).(*reconcilerRunner)
	assert.Equal(t, []attribute.KeyValue{attr}, r.attributes)
	assert.Equal(t, interval, r.interval)
	assert.NotNil(t, r.errorHandler)
	assert.Equal(t, traceProvider, r.tracerProvider)
}

// mockReconciler is a simple mock for the Reconciler interface.
type mockReconciler struct {
	reconcile func(ctx context.Context) error
}

func (m *mockReconciler) Reconcile(ctx context.Context) error {
	return m.reconcile(ctx)
}
