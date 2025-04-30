package mcp

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
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

func (storage *Storage) DeleteAuthorizationRequest(
	ctx context.Context,
	id string,
) error {
	data := protoutil.NewAny(&oauth21proto.AuthorizationRequest{})
	_, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:        id,
			Data:      data,
			Type:      data.TypeUrl,
			DeletedAt: timestamppb.Now(),
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to delete authorization request by ID: %w", err)
	}
	return nil
}

func (storage *Storage) GetSession(ctx context.Context, id string) (*session.Session, error) {
	v := new(session.Session)
	rec, err := storage.client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(v),
		Id:   id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get session by ID: %w", err)
	}

	err = anypb.UnmarshalTo(rec.Record.Data, v, proto.UnmarshalOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	return v, nil
}

// StoreUpstreamOAuth2Token stores the upstream OAuth2 token for a given session and a host
func (storage *Storage) StoreUpstreamOAuth2Token(
	ctx context.Context,
	sessionID string,
	host string,
	token *oauth21proto.TokenResponse,
) error {
	data := protoutil.NewAny(token)
	_, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:   fmt.Sprintf("%s|%s", sessionID, host),
			Data: data,
			Type: data.TypeUrl,
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to store upstream oauth2 token for session: %w", err)
	}
	return nil
}

// GetUpstreamOAuth2Token loads the upstream OAuth2 token for a given session and a host
func (storage *Storage) GetUpstreamOAuth2Token(
	ctx context.Context,
	sessionID string,
	host string,
) (*oauth21proto.TokenResponse, error) {
	v := new(oauth21proto.TokenResponse)
	rec, err := storage.client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(v),
		Id:   fmt.Sprintf("%s|%s", sessionID, host),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream oauth2 token for session: %w", err)
	}

	err = anypb.UnmarshalTo(rec.Record.Data, v, proto.UnmarshalOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal upstream oauth2 token: %w", err)
	}

	return v, nil
}
