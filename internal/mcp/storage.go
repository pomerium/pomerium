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
	req *rfc7591v1.ClientRegistrationRequest,
) (*rfc7591v1.ClientInformationResponse, error) {
	data := protoutil.NewAny(req)
	id := uuid.NewString()
	rec, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:   id,
			Data: data,
			Type: data.TypeUrl,
		}},
	})
	if err != nil {
		return nil, err
	}
	if len(rec.Records) == 0 {
		return nil, fmt.Errorf("no records returned")
	}

	now := rec.Records[0].GetModifiedAt().Seconds
	return getClientInformation(id, now, req), nil
}

func (storage *Storage) GetClientByID(
	ctx context.Context,
	id string,
) (*rfc7591v1.ClientRegistrationRequest, error) {
	rec, err := storage.client.Get(ctx, &databroker.GetRequest{
		Id: id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get client by ID: %w", err)
	}

	v := new(rfc7591v1.ClientRegistrationRequest)
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

func getClientInformation(
	id string,
	issuedAt int64,
	req *rfc7591v1.ClientRegistrationRequest,
) *rfc7591v1.ClientInformationResponse {
	return &rfc7591v1.ClientInformationResponse{
		ClientId:                id,
		ClientIdIssuedAt:        proto.Int64(issuedAt),
		RedirectUris:            req.RedirectUris,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ClientName:              req.ClientName,
		ClientNameLocalized:     req.ClientNameLocalized,
		ClientUri:               req.ClientUri,
		ClientUriLocalized:      req.ClientUriLocalized,
		LogoUri:                 req.LogoUri,
		LogoUriLocalized:        req.LogoUriLocalized,
		Scope:                   req.Scope,
		Contacts:                req.Contacts,
		TosUri:                  req.TosUri,
		TosUriLocalized:         req.TosUriLocalized,
		PolicyUri:               req.PolicyUri,
		PolicyUriLocalized:      req.PolicyUriLocalized,
		JwksUri:                 req.JwksUri,
		Jwks:                    req.Jwks,
		SoftwareId:              req.SoftwareId,
		SoftwareVersion:         req.SoftwareVersion,
		SoftwareStatement:       req.SoftwareStatement,
	}
}
