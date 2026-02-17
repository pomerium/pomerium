package mcp

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	oauth21proto "github.com/pomerium/pomerium/internal/oauth21/gen"
	rfc7591v1 "github.com/pomerium/pomerium/internal/rfc7591"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/protoutil"
)

// handlerStorage defines the storage operations used by Handler.
// This interface exists primarily for testing - the concrete Storage type
// implements it, and tests can provide mock implementations to simulate failures.
type handlerStorage interface {
	RegisterClient(ctx context.Context, req *rfc7591v1.ClientRegistration) (string, error)
	GetClient(ctx context.Context, id string) (*rfc7591v1.ClientRegistration, error)
	CreateAuthorizationRequest(ctx context.Context, req *oauth21proto.AuthorizationRequest) (string, error)
	GetAuthorizationRequest(ctx context.Context, id string) (*oauth21proto.AuthorizationRequest, error)
	DeleteAuthorizationRequest(ctx context.Context, id string) error
	GetSession(ctx context.Context, id string) (*session.Session, error)
	PutSession(ctx context.Context, s *session.Session) error
	StoreUpstreamOAuth2Token(ctx context.Context, host string, userID string, token *oauth21proto.TokenResponse) error
	GetUpstreamOAuth2Token(ctx context.Context, host string, userID string) (*oauth21proto.TokenResponse, error)
	DeleteUpstreamOAuth2Token(ctx context.Context, host string, userID string) error
	PutMCPRefreshToken(ctx context.Context, token *oauth21proto.MCPRefreshToken) error
	GetMCPRefreshToken(ctx context.Context, id string) (*oauth21proto.MCPRefreshToken, error)
	DeleteMCPRefreshToken(ctx context.Context, id string) error
	PutUpstreamMCPToken(ctx context.Context, token *oauth21proto.UpstreamMCPToken) error
	GetUpstreamMCPToken(ctx context.Context, userID, routeID, upstreamServer string) (*oauth21proto.UpstreamMCPToken, error)
	DeleteUpstreamMCPToken(ctx context.Context, userID, routeID, upstreamServer string) error
	PutPendingUpstreamAuth(ctx context.Context, pending *oauth21proto.PendingUpstreamAuth) error
	GetPendingUpstreamAuth(ctx context.Context, stateID string) (*oauth21proto.PendingUpstreamAuth, error)
	DeletePendingUpstreamAuth(ctx context.Context, stateID string) error
	GetPendingUpstreamAuthByUserAndHost(ctx context.Context, userID, host string) (*oauth21proto.PendingUpstreamAuth, error)
	GetUpstreamOAuthClient(ctx context.Context, issuer, downstreamHost string) (*oauth21proto.UpstreamOAuthClient, error)
	PutUpstreamOAuthClient(ctx context.Context, client *oauth21proto.UpstreamOAuthClient) error
}

// Storage implements handlerStorage using a databroker client.
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
	req *rfc7591v1.ClientRegistration,
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
) (*rfc7591v1.ClientRegistration, error) {
	v := new(rfc7591v1.ClientRegistration)
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

// upstreamOAuth2TokenID builds the composite key for an upstream OAuth2 token record.
func upstreamOAuth2TokenID(host, userID string) string {
	return databroker.CompositeRecordID(map[string]any{"host": host, "user_id": userID})
}

// StoreUpstreamOAuth2Token stores the upstream OAuth2 token for a given session and a host
func (storage *Storage) StoreUpstreamOAuth2Token(
	ctx context.Context,
	host string,
	userID string,
	token *oauth21proto.TokenResponse,
) error {
	data := protoutil.NewAny(token)
	_, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:   upstreamOAuth2TokenID(host, userID),
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
	host string,
	userID string,
) (*oauth21proto.TokenResponse, error) {
	v := new(oauth21proto.TokenResponse)
	rec, err := storage.client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(v),
		Id:   upstreamOAuth2TokenID(host, userID),
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

// DeleteUpstreamOAuth2Token removes the upstream OAuth2 token for a given host and user ID
func (storage *Storage) DeleteUpstreamOAuth2Token(
	ctx context.Context,
	host string,
	userID string,
) error {
	data := protoutil.NewAny(&oauth21proto.TokenResponse{})
	_, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:        upstreamOAuth2TokenID(host, userID),
			Data:      data,
			Type:      data.TypeUrl,
			DeletedAt: timestamppb.Now(),
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to delete upstream oauth2 token for session: %w", err)
	}
	return nil
}

// PutMCPRefreshToken stores an MCP refresh token record.
func (storage *Storage) PutMCPRefreshToken(
	ctx context.Context,
	token *oauth21proto.MCPRefreshToken,
) error {
	data := protoutil.NewAny(token)
	_, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:   token.Id,
			Data: data,
			Type: data.TypeUrl,
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to store MCP refresh token: %w", err)
	}
	log.Ctx(ctx).Info().
		Str("record-type", data.TypeUrl).
		Str("record-id", token.Id).
		Str("client-id", token.ClientId).
		Str("user-id", token.UserId).
		Msg("stored mcp refresh token")
	return nil
}

// GetMCPRefreshToken retrieves an MCP refresh token record by ID.
func (storage *Storage) GetMCPRefreshToken(
	ctx context.Context,
	id string,
) (*oauth21proto.MCPRefreshToken, error) {
	v := new(oauth21proto.MCPRefreshToken)
	rec, err := storage.client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(v),
		Id:   id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get MCP refresh token by ID: %w", err)
	}

	err = anypb.UnmarshalTo(rec.Record.Data, v, proto.UnmarshalOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal MCP refresh token: %w", err)
	}

	return v, nil
}

// DeleteMCPRefreshToken removes an MCP refresh token record.
func (storage *Storage) DeleteMCPRefreshToken(
	ctx context.Context,
	id string,
) error {
	data := protoutil.NewAny(&oauth21proto.MCPRefreshToken{})
	_, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:        id,
			Data:      data,
			Type:      data.TypeUrl,
			DeletedAt: timestamppb.Now(),
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to delete MCP refresh token: %w", err)
	}
	log.Ctx(ctx).Info().
		Str("record-id", id).
		Msg("deleted mcp refresh token")
	return nil
}

// upstreamMCPTokenID builds the composite key for an UpstreamMCPToken record.
// All three fields must be non-empty.
func upstreamMCPTokenID(userID, routeID, upstreamServer string) (string, error) {
	if userID == "" || routeID == "" || upstreamServer == "" {
		return "", fmt.Errorf("upstream MCP token requires non-empty user_id, route_id, and upstream_server")
	}
	return databroker.CompositeRecordID(map[string]any{"user_id": userID, "route_id": routeID, "upstream_server": upstreamServer}), nil
}

// PutUpstreamMCPToken stores or updates an upstream MCP token record.
// The record ID is derived from the token's UserId, RouteId, and UpstreamServer fields.
func (storage *Storage) PutUpstreamMCPToken(
	ctx context.Context,
	token *oauth21proto.UpstreamMCPToken,
) error {
	id, err := upstreamMCPTokenID(token.UserId, token.RouteId, token.UpstreamServer)
	if err != nil {
		return err
	}
	data := protoutil.NewAny(token)
	_, err = storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:   id,
			Data: data,
			Type: data.TypeUrl,
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to store upstream MCP token: %w", err)
	}
	log.Ctx(ctx).Info().
		Str("record-type", data.TypeUrl).
		Str("record-id", id).
		Str("user-id", token.UserId).
		Str("route-id", token.RouteId).
		Str("upstream-server", token.UpstreamServer).
		Msg("stored upstream mcp token")
	return nil
}

// GetUpstreamMCPToken retrieves an upstream MCP token by composite key.
func (storage *Storage) GetUpstreamMCPToken(
	ctx context.Context,
	userID, routeID, upstreamServer string,
) (*oauth21proto.UpstreamMCPToken, error) {
	id, err := upstreamMCPTokenID(userID, routeID, upstreamServer)
	if err != nil {
		return nil, err
	}
	v := new(oauth21proto.UpstreamMCPToken)
	rec, err := storage.client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(v),
		Id:   id,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream MCP token: %w", err)
	}

	err = anypb.UnmarshalTo(rec.Record.Data, v, proto.UnmarshalOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal upstream MCP token: %w", err)
	}

	return v, nil
}

// DeleteUpstreamMCPToken removes an upstream MCP token record.
func (storage *Storage) DeleteUpstreamMCPToken(
	ctx context.Context,
	userID, routeID, upstreamServer string,
) error {
	id, err := upstreamMCPTokenID(userID, routeID, upstreamServer)
	if err != nil {
		return err
	}
	data := protoutil.NewAny(&oauth21proto.UpstreamMCPToken{})
	_, err = storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:        id,
			Data:      data,
			Type:      data.TypeUrl,
			DeletedAt: timestamppb.Now(),
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to delete upstream MCP token: %w", err)
	}
	log.Ctx(ctx).Info().
		Str("user-id", userID).
		Str("route-id", routeID).
		Str("upstream-server", upstreamServer).
		Msg("deleted upstream mcp token")
	return nil
}

// PutSession stores a session in the databroker.
func (storage *Storage) PutSession(ctx context.Context, s *session.Session) error {
	_, err := session.Put(ctx, storage.client, s)
	return err
}

// PutPendingUpstreamAuth stores a pending upstream authorization state.
// The state is keyed by its StateId field.
func (storage *Storage) PutPendingUpstreamAuth(
	ctx context.Context,
	pending *oauth21proto.PendingUpstreamAuth,
) error {
	if pending.StateId == "" {
		return fmt.Errorf("pending upstream auth requires non-empty state_id")
	}
	data := protoutil.NewAny(pending)
	_, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:   pending.StateId,
			Data: data,
			Type: data.TypeUrl,
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to store pending upstream auth: %w", err)
	}
	return nil
}

// GetPendingUpstreamAuth retrieves a pending upstream authorization state by its state ID.
func (storage *Storage) GetPendingUpstreamAuth(
	ctx context.Context,
	stateID string,
) (*oauth21proto.PendingUpstreamAuth, error) {
	v := new(oauth21proto.PendingUpstreamAuth)
	rec, err := storage.client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(v),
		Id:   stateID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get pending upstream auth: %w", err)
	}

	err = anypb.UnmarshalTo(rec.Record.Data, v, proto.UnmarshalOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal pending upstream auth: %w", err)
	}

	return v, nil
}

// DeletePendingUpstreamAuth removes a pending upstream authorization state.
func (storage *Storage) DeletePendingUpstreamAuth(
	ctx context.Context,
	stateID string,
) error {
	data := protoutil.NewAny(&oauth21proto.PendingUpstreamAuth{})
	_, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:        stateID,
			Data:      data,
			Type:      data.TypeUrl,
			DeletedAt: timestamppb.Now(),
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to delete pending upstream auth: %w", err)
	}
	return nil
}

// GetPendingUpstreamAuthByUserAndHost looks up a pending upstream auth by userID and downstream host.
// Uses the databroker's native field indexing (user_id + downstream_host) via Query.
func (storage *Storage) GetPendingUpstreamAuthByUserAndHost(
	ctx context.Context,
	userID, host string,
) (*oauth21proto.PendingUpstreamAuth, error) {
	v := new(oauth21proto.PendingUpstreamAuth)
	res, err := storage.client.Query(ctx, &databroker.QueryRequest{
		Type:  protoutil.GetTypeURL(v),
		Limit: 1,
		Filter: &structpb.Struct{Fields: map[string]*structpb.Value{
			"user_id":         structpb.NewStringValue(userID),
			"downstream_host": structpb.NewStringValue(host),
		}},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query pending upstream auth: %w", err)
	}
	if len(res.GetRecords()) == 0 {
		return nil, fmt.Errorf("no pending upstream auth found for user %s and host %s", userID, host)
	}
	if err := anypb.UnmarshalTo(res.GetRecords()[0].GetData(), v, proto.UnmarshalOptions{}); err != nil {
		return nil, fmt.Errorf("failed to unmarshal pending upstream auth: %w", err)
	}
	return v, nil
}

// upstreamOAuthClientID builds the composite key for an UpstreamOAuthClient record.
func upstreamOAuthClientID(issuer, downstreamHost string) string {
	return databroker.CompositeRecordID(map[string]any{"type": "dcr", "issuer": issuer, "downstream_host": downstreamHost})
}

// GetUpstreamOAuthClient retrieves a cached DCR client registration by AS issuer and downstream host.
func (storage *Storage) GetUpstreamOAuthClient(
	ctx context.Context,
	issuer, downstreamHost string,
) (*oauth21proto.UpstreamOAuthClient, error) {
	v := new(oauth21proto.UpstreamOAuthClient)
	rec, err := storage.client.Get(ctx, &databroker.GetRequest{
		Type: protoutil.GetTypeURL(v),
		Id:   upstreamOAuthClientID(issuer, downstreamHost),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get upstream OAuth client: %w", err)
	}

	err = anypb.UnmarshalTo(rec.Record.Data, v, proto.UnmarshalOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal upstream OAuth client: %w", err)
	}

	return v, nil
}

// PutUpstreamOAuthClient stores a DCR client registration.
// DCR is per-instance (not per-user): one registration is shared across all users
// for a given AS issuer + downstream host combination.
func (storage *Storage) PutUpstreamOAuthClient(
	ctx context.Context,
	client *oauth21proto.UpstreamOAuthClient,
) error {
	if client.Issuer == "" || client.DownstreamHost == "" {
		return fmt.Errorf("upstream OAuth client requires non-empty issuer and downstream_host")
	}
	id := upstreamOAuthClientID(client.Issuer, client.DownstreamHost)
	data := protoutil.NewAny(client)
	_, err := storage.client.Put(ctx, &databroker.PutRequest{
		Records: []*databroker.Record{{
			Id:   id,
			Data: data,
			Type: data.TypeUrl,
		}},
	})
	if err != nil {
		return fmt.Errorf("failed to store upstream OAuth client: %w", err)
	}
	log.Ctx(ctx).Info().
		Str("record-id", id).
		Str("issuer", client.Issuer).
		Str("downstream-host", client.DownstreamHost).
		Str("client-id", client.ClientId).
		Msg("stored upstream oauth client registration")
	return nil
}
