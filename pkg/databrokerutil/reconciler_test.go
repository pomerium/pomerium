package databrokerutil

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/databroker/mock_databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

func TestReconciler(t *testing.T) {
	t.Parallel()

	cmpFn := func(r1, r2 *databroker.Record) bool {
		return cmp.Equal(r1, r2, protocmp.Transform())
	}

	initCurrent := func() (databroker.RecordSetBundle, func(records []*databroker.Record)) {
		current := databroker.RecordSetBundle{}
		setCurrentState := func(records []*databroker.Record) {
			clear(current)
			for _, r := range records {
				if r.DeletedAt == nil {
					current.Add(r)
				}
			}
		}
		return current, setCurrentState
	}

	t.Run("no changes", func(t *testing.T) {
		t.Parallel()

		exampleRecord := &databroker.Record{
			Type: "test.Type",
			Id:   "record-1",
			Data: protoutil.ToAny(map[string]any{"name": "test"}),
		}

		// Current and target both contain the same record, with the same data.
		current, setCurrentState := initCurrent()
		current.Add(exampleRecord)
		target := databroker.RecordSetBundle{}
		target.Add(proto.CloneOf(exampleRecord))

		// No databroker calls expected because there are no changes.
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

		r := NewReconciler(
			databroker.NewStaticClientGetter(client),
			func(context.Context) (databroker.RecordSetBundle, error) {
				return current, nil
			},
			func(context.Context) (databroker.RecordSetBundle, error) {
				return target, nil
			},
			setCurrentState,
			cmpFn,
		)

		err := r.Reconcile(t.Context())
		require.NoError(t, err)
		assert.Empty(t, current)
	})

	t.Run("add record", func(t *testing.T) {
		t.Parallel()

		exampleRecord := &databroker.Record{
			Type: "test.Type",
			Id:   "record-1",
			Data: protoutil.ToAny(map[string]any{"name": "test"}),
		}

		// Current empty, target has one record.
		current, setCurrentState := initCurrent()
		target := databroker.RecordSetBundle{}
		target.Add(exampleRecord)

		// This should result in a request to add the one target record.
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().
			Put(gomock.Any(), mock_databroker.PutRequestFor(exampleRecord)).
			Return(&databroker.PutResponse{}, nil)

		r := NewReconciler(
			databroker.NewStaticClientGetter(client),
			func(context.Context) (databroker.RecordSetBundle, error) {
				return current, nil
			},
			func(context.Context) (databroker.RecordSetBundle, error) {
				return target, nil
			},
			setCurrentState,
			cmpFn,
		)

		err := r.Reconcile(t.Context())
		require.NoError(t, err)
		testutil.AssertProtoEqual(t, target, current)
	})

	t.Run("delete record", func(t *testing.T) {
		t.Parallel()

		exampleRecord := &databroker.Record{
			Type: "test.Type",
			Id:   "record-1",
			Data: protoutil.ToAny(map[string]any{"name": "test"}),
		}

		// Current has one record, target empty.
		current, setCurrentState := initCurrent()
		current.Add(exampleRecord)
		target := databroker.RecordSetBundle{}

		// This should result in a request to delete the one current record.
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().
			Put(gomock.Any(), mock_databroker.DeleteRequestFor(exampleRecord)).
			Return(&databroker.PutResponse{}, nil)

		r := NewReconciler(
			databroker.NewStaticClientGetter(client),
			func(context.Context) (databroker.RecordSetBundle, error) {
				return current, nil
			},
			func(context.Context) (databroker.RecordSetBundle, error) {
				return target, nil
			},
			setCurrentState,
			cmpFn,
		)

		err := r.Reconcile(t.Context())
		require.NoError(t, err)
		assert.Empty(t, current)
	})

	t.Run("modify record", func(t *testing.T) {
		t.Parallel()

		oldRecord := &databroker.Record{
			Type: "test.Type",
			Id:   "record-1",
			Data: protoutil.ToAny(map[string]any{"name": "old-value"}),
		}
		newRecord := &databroker.Record{
			Type: "test.Type",
			Id:   "record-1",
			Data: protoutil.ToAny(map[string]any{"name": "new-value"}),
		}

		// Current and target both contain the same record, but with different data.
		current, setCurrentState := initCurrent()
		current.Add(oldRecord)
		target := databroker.RecordSetBundle{}
		target.Add(newRecord)

		// This should result in a Put call to update the record.
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().
			Put(gomock.Any(), mock_databroker.PutRequestFor(newRecord)).
			Return(&databroker.PutResponse{}, nil)

		r := NewReconciler(
			databroker.NewStaticClientGetter(client),
			func(context.Context) (databroker.RecordSetBundle, error) {
				return current, nil
			},
			func(context.Context) (databroker.RecordSetBundle, error) {
				return target, nil
			},
			setCurrentState,
			cmpFn,
		)

		err := r.Reconcile(t.Context())
		require.NoError(t, err)
		testutil.AssertProtoEqual(t, target, current)
	})

	t.Run("multiple record types", func(t *testing.T) {
		t.Parallel()

		a1 := &databroker.Record{
			Type: "type.A",
			Id:   "record-1",
			Data: protoutil.ToAny(map[string]any{"value": "a1"}),
		}
		a1Modified := &databroker.Record{
			Type: "type.A",
			Id:   "record-1",
			Data: protoutil.ToAny(map[string]any{"value": "a1-modified"}),
		}
		b1 := &databroker.Record{
			Type: "type.B",
			Id:   "record-2",
			Data: protoutil.ToAny(map[string]any{"value": "b1"}),
		}

		current, setCurrentState := initCurrent()
		current.Add(a1)
		target := databroker.RecordSetBundle{}
		target.Add(a1Modified)
		target.Add(b1)

		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().
			Put(gomock.Any(), mock_databroker.PutRequestFor(a1Modified, b1)).
			Return(&databroker.PutResponse{}, nil)

		r := NewReconciler(
			databroker.NewStaticClientGetter(client),
			func(context.Context) (databroker.RecordSetBundle, error) {
				return current, nil
			},
			func(context.Context) (databroker.RecordSetBundle, error) {
				return target, nil
			},
			setCurrentState,
			cmpFn,
		)

		err := r.Reconcile(t.Context())
		require.NoError(t, err)
		testutil.AssertProtoEqual(t, target, current)
	})

	t.Run("databroker client change", func(t *testing.T) {
		t.Parallel()

		exampleRecord := &databroker.Record{
			Type: "test.Type",
			Id:   "record-1",
			Data: protoutil.ToAny(map[string]any{"name": "test"}),
		}

		current, setCurrentState := initCurrent()
		target := databroker.RecordSetBundle{}

		var currentClient databroker.DataBrokerServiceClient
		clientGetter := databroker.ClientGetterFunc(
			func() databroker.DataBrokerServiceClient { return currentClient })

		ctrl := gomock.NewController(t)

		r := NewReconciler(
			clientGetter,
			func(context.Context) (databroker.RecordSetBundle, error) {
				return current, nil
			},
			func(context.Context) (databroker.RecordSetBundle, error) {
				return target, nil
			},
			setCurrentState,
			cmpFn,
		)

		// First add a databroker record.
		target.Add(exampleRecord)

		client1 := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client1.EXPECT().
			Put(gomock.Any(), mock_databroker.PutRequestFor(exampleRecord)).
			Return(&databroker.PutResponse{}, nil)
		currentClient = client1

		err := r.Reconcile(t.Context())
		require.NoError(t, err)
		testutil.AssertProtoEqual(t, target, current)

		// Then delete this record after changing the databroker client.
		// The Reconcile() method should use the updated client.
		clear(target)

		client2 := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client2.EXPECT().
			Put(gomock.Any(), mock_databroker.DeleteRequestFor(exampleRecord)).
			Return(&databroker.PutResponse{}, nil)
		currentClient = client2

		err = r.Reconcile(t.Context())
		require.NoError(t, err)
		testutil.AssertProtoEqual(t, target, current)
	})

	t.Run("current state builder error", func(t *testing.T) {
		t.Parallel()

		// No databroker calls expected if state building fails.
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

		builderErr := errors.New("failed to build current state")

		r := NewReconciler(
			databroker.NewStaticClientGetter(client),
			func(context.Context) (databroker.RecordSetBundle, error) {
				return nil, builderErr
			},
			func(context.Context) (databroker.RecordSetBundle, error) {
				return databroker.RecordSetBundle{}, nil
			},
			func([]*databroker.Record) {},
			cmpFn,
		)

		err := r.Reconcile(t.Context())
		require.Error(t, err)
		assert.ErrorIs(t, err, builderErr)
	})

	t.Run("target state builder error", func(t *testing.T) {
		t.Parallel()

		// No databroker calls expected if state building fails.
		ctrl := gomock.NewController(t)
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

		builderErr := errors.New("failed to build target state")

		r := NewReconciler(
			databroker.NewStaticClientGetter(client),
			func(context.Context) (databroker.RecordSetBundle, error) {
				return databroker.RecordSetBundle{}, nil
			},
			func(context.Context) (databroker.RecordSetBundle, error) {
				return nil, builderErr
			},
			func([]*databroker.Record) {},
			cmpFn,
		)

		err := r.Reconcile(t.Context())
		require.Error(t, err)
		assert.ErrorIs(t, err, builderErr)
	})

	t.Run("put error", func(t *testing.T) {
		t.Parallel()

		current, setCurrentState := initCurrent()
		target := databroker.RecordSetBundle{}
		target.Add(&databroker.Record{
			Type: "test.Type",
			Id:   "record-1",
			Data: protoutil.ToAny(map[string]any{"name": "test"}),
		})

		ctrl := gomock.NewController(t)

		putErr := errors.New("failed to put records")
		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)
		client.EXPECT().
			Put(gomock.Any(), gomock.Any()).
			Return(nil, putErr)

		r := NewReconciler(
			databroker.NewStaticClientGetter(client),
			func(context.Context) (databroker.RecordSetBundle, error) {
				return current, nil
			},
			func(context.Context) (databroker.RecordSetBundle, error) {
				return target, nil
			},
			setCurrentState,
			cmpFn,
		)

		err := r.Reconcile(t.Context())
		require.Error(t, err)
		assert.ErrorIs(t, err, putErr)
		assert.Empty(t, current) // current state should not be updated if there was an error
	})

	t.Run("context cancellation", func(t *testing.T) {
		t.Parallel()

		ctrl := gomock.NewController(t)

		client := mock_databroker.NewMockDataBrokerServiceClient(ctrl)

		ctx, cancel := context.WithCancel(t.Context())
		cancel() // cancel immediately

		r := NewReconciler(
			databroker.NewStaticClientGetter(client),
			func(context.Context) (databroker.RecordSetBundle, error) {
				return nil, ctx.Err()
			},
			func(context.Context) (databroker.RecordSetBundle, error) {
				return databroker.RecordSetBundle{}, nil
			},
			func([]*databroker.Record) {},
			cmpFn,
		)

		err := r.Reconcile(ctx)
		require.Error(t, err)
		assert.ErrorIs(t, err, context.Canceled)
	})

	t.Run("trace provider option", func(t *testing.T) {
		t.Parallel()

		traceProvider := noop.NewTracerProvider()

		r := NewReconciler(nil, nil, nil, nil, nil,
			WithReconcilerTracerProvider(traceProvider),
		).(*reconciler)
		assert.Equal(t, traceProvider, r.telemetry.GetTracerProvider())
	})
}
