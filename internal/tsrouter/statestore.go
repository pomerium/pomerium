package tsrouter

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/wrapperspb"
	"tailscale.com/ipn"

	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type databrokerStateStore struct {
	hostname string
	client   databroker.DataBrokerServiceClient
}

// NewDataBrokerStateStore creates a new tailscale state store that stores
// data in the databroker.
func NewDataBrokerStateStore(hostname string, client databroker.DataBrokerServiceClient) ipn.StateStore {
	return &databrokerStateStore{
		hostname: hostname,
		client:   client,
	}
}

func (s *databrokerStateStore) ReadState(id ipn.StateKey) ([]byte, error) {
	res, err := s.client.Get(context.Background(), &databroker.GetRequest{
		Type: GetRecordTypeForState(),
		Id:   GetRecordIDForState(s.hostname, id),
	})
	if databroker.IsNotFound(err) {
		return nil, ipn.ErrStateNotExist
	} else if err != nil {
		return nil, fmt.Errorf("tsrouter: error reading state from databroker (hostname=%s key=%s): %w", s.hostname, id, err)
	}
	var bs wrapperspb.BytesValue
	err = res.GetRecord().GetData().UnmarshalTo(&bs)
	if err == nil {
		return bs.Value, nil
	}
	// data should be stored as bytes, if not just return nil
	return nil, nil
}

func (s *databrokerStateStore) WriteState(id ipn.StateKey, bs []byte) error {
	_, err := s.client.Put(context.Background(), &databroker.PutRequest{
		Records: []*databroker.Record{{
			Type: GetRecordTypeForState(),
			Id:   GetRecordIDForState(s.hostname, id),
			Data: protoutil.NewAnyBytes(bs),
		}},
	})
	if err != nil {
		return fmt.Errorf("tsrouter: error writing state to databroker (hostname=%s key=%s): %w", s.hostname, id, err)
	}
	return nil
}

// GetRecordTypeForState gets the record type for state.
func GetRecordTypeForState() string {
	return "tailscale.com/node-state"
}

// GetRecordIDForState gets the record id for state.
func GetRecordIDForState(hostname string, key ipn.StateKey) string {
	return fmt.Sprintf("%s/%s", hostname, key)
}
