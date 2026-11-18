package tsrouter

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel/attribute"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"tailscale.com/ipn"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// StateDataBrokerRecordType is the record type for tailscale device state.
const StateDataBrokerRecordType = "tailscale.com/ipn/state"

type tsListenerStateStore struct {
	ctx              context.Context
	listener         *tsListener
	dataBrokerClient databrokerpb.DataBrokerServiceClient
}

func newTSListenerStateStore(
	ctx context.Context,
	listener *tsListener,
	dataBrokerClient databrokerpb.DataBrokerServiceClient,
) ipn.StateStore {
	return &tsListenerStateStore{
		ctx:              ctx,
		listener:         listener,
		dataBrokerClient: dataBrokerClient,
	}
}

func (store *tsListenerStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	ctx, op := store.listener.telemetry.Start(store.ctx, "ReadState",
		attribute.String("state-key", string(id)))
	defer op.Complete()

	res, err := store.dataBrokerClient.Get(ctx, &databrokerpb.GetRequest{
		Type: StateDataBrokerRecordType,
		Id:   store.listener.Settings.Hostname.Value + "/" + string(id),
	})
	if status.Code(err) == codes.NotFound {
		// ipn has a special error type for not found
		return nil, ipn.ErrStateNotExist
	} else if err != nil {
		return nil, op.Failure(fmt.Errorf("error reading tailscale state from databroker: %w", err))
	}

	var data wrapperspb.BytesValue
	err = res.GetRecord().GetData().UnmarshalTo(&data)
	if err != nil {
		return nil, op.Failure(fmt.Errorf("error reading tailscale state from databroker, unexpected data type %T: %w",
			res.GetRecord().GetData(), err))
	}

	return data.GetValue(), nil
}

func (store *tsListenerStateStore) WriteState(id ipn.StateKey, bs []byte) error {
	ctx, op := store.listener.telemetry.Start(store.ctx, "WriteState",
		attribute.String("state-key", string(id)))
	defer op.Complete()

	record := &databrokerpb.Record{
		Type: StateDataBrokerRecordType,
		Id:   store.listener.Settings.Hostname.Value + "/" + string(id),
		Data: protoutil.NewAnyBytes(bs),
	}
	if len(bs) == 0 {
		record.DeletedAt = timestamppb.Now()
	}

	_, err := store.dataBrokerClient.Put(ctx, &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{record},
	})
	if err != nil {
		return op.Failure(fmt.Errorf("error writing tailscale state to databroker: %w", err))
	}
	return nil
}
