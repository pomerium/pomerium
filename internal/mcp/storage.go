package mcp

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

type Storage struct {
	client databroker.DataBrokerServiceClient
}

// NewStorage creates a new Storage instance.
func NewStorage(
	client databroker.DataBrokerServiceClient,
) *Storage {
	return &Storage{
		client: client,
	}
}

func (storage *Storage) RegisterClient(
	ctx context.Context,
	req *rfc7591v1.ClientMetadata,
) (string, error) {
	data := protoutil.NewAny(req)
	id := uuid.NewString()
	_, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:   id,
			Data: data,
			Type: data.TypeUrl,
		}},
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func (storage *Storage) GetClient(
	ctx context.Context,
	id string,
) (*rfc7591v1.ClientMetadata, error) {
	v := new(rfc7591v1.ClientMetadata)
	rec, err := storage.client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(v),
		Id:   id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get client by ID: %w", err)
	}

	err = anypb.UnmarshalTo(rec.Record.Data, v, proto.UnmarshalOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal client registration request: %w", err)
	}

	return v, nil
}

func (storage *Storage) CreateAuthorizationRequest(
	ctx context.Context,
	req *oauth21proto.AuthorizationRequest,
) (string, error) {
	data := protoutil.NewAny(req)
	id := uuid.NewString()
	_, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:   id,
			Data: data,
			Type: data.TypeUrl,
		}},
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

func (storage *Storage) GetAuthorizationRequest(
	ctx context.Context,
	id string,
) (*oauth21proto.AuthorizationRequest, error) {
	v := new(oauth21proto.AuthorizationRequest)
	rec, err := storage.client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(v),
		Id:   id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get authorization request by ID: %w", err)
	}

	err = anypb.UnmarshalTo(rec.Record.Data, v, proto.UnmarshalOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal authorization request: %w", err)
	}

	return v, nil
}
