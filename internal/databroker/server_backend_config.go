package databroker

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/volatiletech/null/v9"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

// GlobalSettingsID is the default global settings id if none is provided.
const GlobalSettingsID = "78408adf-56e4-41d0-af6a-ca1b2d8d2cb6"

type backendConfigServer struct {
	*backendServer
}

func (srv *backendConfigServer) CreateKeyPair(
	ctx context.Context,
	req *connect.Request[configpb.CreateKeyPairRequest],
) (*connect.Response[configpb.CreateKeyPairResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.CreateKeyPair")
	defer span.End()

	entity := proto.CloneOf(req.Msg.GetKeyPair())
	if entity == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("key pair is required"))
	}
	entity.CreatedAt = timestamppb.Now()

	record, err := srv.createEntity(ctx, entity, &entity.Id)
	if err != nil {
		return nil, err
	}
	entity.ModifiedAt = record.GetModifiedAt()

	return connect.NewResponse(&configpb.CreateKeyPairResponse{
		KeyPair: entity,
	}), nil
}

func (srv *backendConfigServer) CreatePolicy(
	ctx context.Context,
	req *connect.Request[configpb.CreatePolicyRequest],
) (*connect.Response[configpb.CreatePolicyResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.CreatePolicy")
	defer span.End()

	entity := proto.CloneOf(req.Msg.GetPolicy())
	if entity == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("policy is required"))
	}
	entity.CreatedAt = timestamppb.Now()

	record, err := srv.createEntity(ctx, entity, &entity.Id)
	if err != nil {
		return nil, err
	}
	entity.ModifiedAt = record.GetModifiedAt()

	return connect.NewResponse(&configpb.CreatePolicyResponse{
		Policy: entity,
	}), nil
}

func (srv *backendConfigServer) CreateRoute(
	ctx context.Context,
	req *connect.Request[configpb.CreateRouteRequest],
) (*connect.Response[configpb.CreateRouteResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.CreateRoute")
	defer span.End()

	entity := proto.CloneOf(req.Msg.GetRoute())
	if entity == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("route is required"))
	}
	entity.CreatedAt = timestamppb.Now()

	record, err := srv.createEntity(ctx, entity, &entity.Id)
	if err != nil {
		return nil, err
	}
	entity.ModifiedAt = record.GetModifiedAt()

	return connect.NewResponse(&configpb.CreateRouteResponse{
		Route: entity,
	}), nil
}

func (srv *backendConfigServer) CreateServiceAccount(
	ctx context.Context,
	req *connect.Request[configpb.CreateServiceAccountRequest],
) (*connect.Response[configpb.CreateServiceAccountResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.CreateServiceAccount")
	defer span.End()

	if req.Msg.GetServiceAccount() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service account is required"))
	}

	entity := &user.ServiceAccount{
		Id:          req.Msg.ServiceAccount.GetId(),
		NamespaceId: req.Msg.ServiceAccount.NamespaceId,
		Description: req.Msg.ServiceAccount.Description,
		UserId:      req.Msg.ServiceAccount.GetUserId(),
		ExpiresAt:   req.Msg.ServiceAccount.ExpiresAt,
		IssuedAt:    timestamppb.Now(),
		AccessedAt:  timestamppb.Now(),
	}
	if entity.Id == "" {
		entity.Id = uuid.NewString()
	}
	id := &entity.Id
	record, err := srv.createEntity(ctx, entity, &id)
	if err != nil {
		return nil, err
	}

	srv.mu.RLock()
	sharedKey := srv.sharedKey
	srv.mu.RUnlock()
	var expiresAt null.Time
	if entity.ExpiresAt.IsValid() {
		expiresAt = null.TimeFrom(entity.ExpiresAt.AsTime())
	}
	jwt, err := cryptutil.SignServiceAccount(sharedKey, entity.Id, entity.UserId, entity.IssuedAt.AsTime(), expiresAt)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error signing service account: %w", err))
	}

	return connect.NewResponse(&configpb.CreateServiceAccountResponse{
		ServiceAccount: userServiceAccountToConfigServiceAccount(record, entity),
		Jwt:            jwt,
	}), nil
}

func (srv *backendConfigServer) DeleteKeyPair(
	ctx context.Context,
	req *connect.Request[configpb.DeleteKeyPairRequest],
) (*connect.Response[configpb.DeleteKeyPairResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.DeleteKeyPair")
	defer span.End()

	if req.Msg.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("key pair id is required"))
	}

	entity := &configpb.KeyPair{Id: proto.String(req.Msg.GetId())}
	err := srv.deleteEntity(ctx, entity)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&configpb.DeleteKeyPairResponse{}), nil
}

func (srv *backendConfigServer) DeletePolicy(
	ctx context.Context,
	req *connect.Request[configpb.DeletePolicyRequest],
) (*connect.Response[configpb.DeletePolicyResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.DeletePolicy")
	defer span.End()

	if req.Msg.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("policy id is required"))
	}

	entity := &configpb.Policy{Id: proto.String(req.Msg.GetId())}
	err := srv.deleteEntity(ctx, entity)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&configpb.DeletePolicyResponse{}), nil
}

func (srv *backendConfigServer) DeleteRoute(
	ctx context.Context,
	req *connect.Request[configpb.DeleteRouteRequest],
) (*connect.Response[configpb.DeleteRouteResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.DeleteRoute")
	defer span.End()

	if req.Msg.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("route id is required"))
	}

	entity := &configpb.Route{Id: proto.String(req.Msg.GetId())}
	err := srv.deleteEntity(ctx, entity)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&configpb.DeleteRouteResponse{}), nil
}

func (srv *backendConfigServer) DeleteServiceAccount(
	ctx context.Context,
	req *connect.Request[configpb.DeleteServiceAccountRequest],
) (*connect.Response[configpb.DeleteServiceAccountResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.DeleteServiceAccount")
	defer span.End()

	if req.Msg.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service account id is required"))
	}

	entity := &user.ServiceAccount{Id: req.Msg.GetId()}
	err := srv.deleteEntity(ctx, entity)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&configpb.DeleteServiceAccountResponse{}), nil
}

func (srv *backendConfigServer) GetKeyPair(
	ctx context.Context,
	req *connect.Request[configpb.GetKeyPairRequest],
) (*connect.Response[configpb.GetKeyPairResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.GetKeyPair")
	defer span.End()

	if req.Msg.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("id is required"))
	}

	entity := &configpb.KeyPair{
		Id: proto.String(req.Msg.GetId()),
	}
	record, err := srv.getEntity(ctx, entity)
	if err != nil {
		return nil, err
	}
	entity.ModifiedAt = record.GetModifiedAt()

	return connect.NewResponse(&configpb.GetKeyPairResponse{
		KeyPair: entity,
	}), nil
}

func (srv *backendConfigServer) GetPolicy(
	ctx context.Context,
	req *connect.Request[configpb.GetPolicyRequest],
) (*connect.Response[configpb.GetPolicyResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.GetPolicy")
	defer span.End()

	if req.Msg.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("id is required"))
	}

	entity := &configpb.Policy{
		Id: proto.String(req.Msg.GetId()),
	}
	record, err := srv.getEntity(ctx, entity)
	if err != nil {
		return nil, err
	}
	entity.ModifiedAt = record.GetModifiedAt()

	return connect.NewResponse(&configpb.GetPolicyResponse{
		Policy: entity,
	}), nil
}

func (srv *backendConfigServer) GetRoute(
	ctx context.Context,
	req *connect.Request[configpb.GetRouteRequest],
) (*connect.Response[configpb.GetRouteResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.GetRoute")
	defer span.End()

	if req.Msg.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("id is required"))
	}

	entity := &configpb.Route{
		Id: proto.String(req.Msg.GetId()),
	}
	record, err := srv.getEntity(ctx, entity)
	if err != nil {
		return nil, err
	}
	entity.ModifiedAt = record.GetModifiedAt()

	return connect.NewResponse(&configpb.GetRouteResponse{
		Route: entity,
	}), nil
}

func (srv *backendConfigServer) GetServerInfo(
	_ context.Context,
	_ *connect.Request[configpb.GetServerInfoRequest],
) (*connect.Response[configpb.GetServerInfoResponse], error) {
	return connect.NewResponse(&configpb.GetServerInfoResponse{
		ServerType: configpb.ServerType_SERVER_TYPE_CORE,
		Version:    version.FullVersion(),
	}), nil
}

func (srv *backendConfigServer) GetServiceAccount(
	ctx context.Context,
	req *connect.Request[configpb.GetServiceAccountRequest],
) (*connect.Response[configpb.GetServiceAccountResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.GetServiceAccount")
	defer span.End()

	if req.Msg.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("id is required"))
	}

	entity := &user.ServiceAccount{
		Id: req.Msg.GetId(),
	}
	record, err := srv.getEntity(ctx, entity)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&configpb.GetServiceAccountResponse{
		ServiceAccount: userServiceAccountToConfigServiceAccount(record, entity),
	}), nil
}

func (srv *backendConfigServer) GetSettings(
	ctx context.Context,
	req *connect.Request[configpb.GetSettingsRequest],
) (*connect.Response[configpb.GetSettingsResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.GetSettings")
	defer span.End()

	entity := new(configpb.Settings)
	switch req.Msg.For.(type) {
	case *configpb.GetSettingsRequest_ClusterId:
		// core only supports a single cluster, so always return not found
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("settings not found"))
	case *configpb.GetSettingsRequest_Id:
		// core only supports a single settings with the GlobalSettingsID
		// any other id should return not found
		if req.Msg.GetId() != GlobalSettingsID {
			return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("settings not found"))
		}
		entity.Id = proto.String(req.Msg.GetId())
	default:
		entity.Id = proto.String(GlobalSettingsID)
	}

	record, err := srv.getEntity(ctx, entity)
	// for settings, treat a not found error as an empty settings object
	if err != nil && !storage.IsNotFound(err) {
		return nil, err
	}
	entity.ModifiedAt = record.GetModifiedAt()

	return connect.NewResponse(&configpb.GetSettingsResponse{
		Settings: entity,
	}), nil
}

func (srv *backendConfigServer) ListKeyPairs(
	ctx context.Context,
	req *connect.Request[configpb.ListKeyPairsRequest],
) (*connect.Response[configpb.ListKeyPairsResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.ListKeyPairs")
	defer span.End()

	recordType := grpcutil.GetTypeURL(new(configpb.KeyPair))

	records, totalCount, err := listRecords[configpb.KeyPair](ctx, srv, recordType,
		req.Msg.Offset, req.Msg.Limit,
		req.Msg.Filter, req.Msg.OrderBy)
	if err != nil {
		return nil, err
	}

	entities := make([]*configpb.KeyPair, len(records))
	for i, r := range records {
		entities[i] = new(configpb.KeyPair)
		err = r.Data.UnmarshalTo(entities[i])
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error converting record to key pair: %w", err))
		}
		entities[i].ModifiedAt = r.ModifiedAt
	}

	return connect.NewResponse(&configpb.ListKeyPairsResponse{
		KeyPairs:   entities,
		TotalCount: totalCount,
	}), nil
}

func (srv *backendConfigServer) ListPolicies(
	ctx context.Context,
	req *connect.Request[configpb.ListPoliciesRequest],
) (*connect.Response[configpb.ListPoliciesResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.ListPolicies")
	defer span.End()

	recordType := grpcutil.GetTypeURL(new(configpb.Policy))

	records, totalCount, err := listRecords[configpb.Policy](ctx, srv, recordType,
		req.Msg.Offset, req.Msg.Limit,
		req.Msg.Filter, req.Msg.OrderBy)
	if err != nil {
		return nil, err
	}

	entities := make([]*configpb.Policy, len(records))
	for i, r := range records {
		entities[i] = new(configpb.Policy)
		err = r.Data.UnmarshalTo(entities[i])
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error converting record to policy: %w", err))
		}
		entities[i].ModifiedAt = r.ModifiedAt
	}

	return connect.NewResponse(&configpb.ListPoliciesResponse{
		Policies:   entities,
		TotalCount: totalCount,
	}), nil
}

func (srv *backendConfigServer) ListRoutes(
	ctx context.Context,
	req *connect.Request[configpb.ListRoutesRequest],
) (*connect.Response[configpb.ListRoutesResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.ListRoutes")
	defer span.End()

	recordType := grpcutil.GetTypeURL(new(configpb.Route))

	records, totalCount, err := listRecords[configpb.Route](ctx, srv, recordType,
		req.Msg.Offset, req.Msg.Limit,
		req.Msg.Filter, req.Msg.OrderBy)
	if err != nil {
		return nil, err
	}

	entities := make([]*configpb.Route, len(records))
	for i, r := range records {
		entities[i] = new(configpb.Route)
		err = r.Data.UnmarshalTo(entities[i])
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error converting record to route: %w", err))
		}
		entities[i].ModifiedAt = r.ModifiedAt
	}

	return connect.NewResponse(&configpb.ListRoutesResponse{
		Routes:     entities,
		TotalCount: totalCount,
	}), nil
}

func (srv *backendConfigServer) ListServiceAccounts(
	ctx context.Context,
	req *connect.Request[configpb.ListServiceAccountsRequest],
) (*connect.Response[configpb.ListServiceAccountsResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.ListServiceAccounts")
	defer span.End()

	recordType := grpcutil.GetTypeURL(new(user.ServiceAccount))
	records, totalCount, err := listRecords[user.ServiceAccount](ctx, srv, recordType,
		req.Msg.Offset, req.Msg.Limit,
		req.Msg.Filter, req.Msg.OrderBy)
	if err != nil {
		return nil, err
	}

	entities := make([]*configpb.ServiceAccount, len(records))
	for i, r := range records {
		var data user.ServiceAccount
		err = r.Data.UnmarshalTo(&data)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error converting record to service account: %w", err))
		}
		entities[i] = userServiceAccountToConfigServiceAccount(r, &data)
	}

	return connect.NewResponse(&configpb.ListServiceAccountsResponse{
		ServiceAccounts: entities,
		TotalCount:      totalCount,
	}), nil
}

func (srv *backendConfigServer) ListSettings(
	ctx context.Context,
	req *connect.Request[configpb.ListSettingsRequest],
) (*connect.Response[configpb.ListSettingsResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.ListSettings")
	defer span.End()

	recordType := grpcutil.GetTypeURL(new(configpb.Settings))

	records, totalCount, err := listRecords[configpb.Settings](ctx, srv, recordType,
		req.Msg.Offset, req.Msg.Limit,
		req.Msg.Filter, req.Msg.OrderBy)
	if err != nil {
		return nil, err
	}

	entities := make([]*configpb.Settings, len(records))
	for i, r := range records {
		entities[i] = new(configpb.Settings)
		err = r.Data.UnmarshalTo(entities[i])
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error converting record to settings: %w", err))
		}
		entities[i].ModifiedAt = r.ModifiedAt
	}

	return connect.NewResponse(&configpb.ListSettingsResponse{
		Settings:   entities,
		TotalCount: totalCount,
	}), nil
}

func (srv *backendConfigServer) UpdateKeyPair(
	ctx context.Context,
	req *connect.Request[configpb.UpdateKeyPairRequest],
) (*connect.Response[configpb.UpdateKeyPairResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.UpdateKeyPair")
	defer span.End()

	entity := proto.CloneOf(req.Msg.GetKeyPair())
	if entity == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("key pair is required"))
	} else if entity.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("key pair id is required"))
	}

	original := proto.CloneOf(entity)
	_, err := srv.getEntity(ctx, original)
	if err != nil {
		return nil, err
	}

	entity.CreatedAt = original.CreatedAt
	record, err := srv.putEntity(ctx, entity)
	if err != nil {
		return nil, err
	}
	entity.ModifiedAt = record.ModifiedAt

	return connect.NewResponse(&configpb.UpdateKeyPairResponse{
		KeyPair: entity,
	}), nil
}

func (srv *backendConfigServer) UpdatePolicy(
	ctx context.Context,
	req *connect.Request[configpb.UpdatePolicyRequest],
) (*connect.Response[configpb.UpdatePolicyResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.UpdatePolicy")
	defer span.End()

	entity := proto.CloneOf(req.Msg.GetPolicy())
	if entity == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("policy is required"))
	} else if entity.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("policy id is required"))
	}

	original := proto.CloneOf(entity)
	_, err := srv.getEntity(ctx, original)
	if err != nil {
		return nil, err
	}

	entity.CreatedAt = original.CreatedAt
	record, err := srv.putEntity(ctx, entity)
	if err != nil {
		return nil, err
	}
	entity.ModifiedAt = record.ModifiedAt

	return connect.NewResponse(&configpb.UpdatePolicyResponse{
		Policy: entity,
	}), nil
}

func (srv *backendConfigServer) UpdateRoute(
	ctx context.Context,
	req *connect.Request[configpb.UpdateRouteRequest],
) (*connect.Response[configpb.UpdateRouteResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.UpdateRoute")
	defer span.End()

	entity := proto.CloneOf(req.Msg.GetRoute())
	if entity == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("route is required"))
	} else if entity.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("route id is required"))
	}

	original := proto.CloneOf(entity)
	_, err := srv.getEntity(ctx, original)
	if err != nil {
		return nil, err
	}

	entity.CreatedAt = original.CreatedAt
	record, err := srv.putEntity(ctx, entity)
	if err != nil {
		return nil, err
	}
	entity.ModifiedAt = record.ModifiedAt

	return connect.NewResponse(&configpb.UpdateRouteResponse{
		Route: entity,
	}), nil
}

func (srv *backendConfigServer) UpdateServiceAccount(
	ctx context.Context,
	req *connect.Request[configpb.UpdateServiceAccountRequest],
) (*connect.Response[configpb.UpdateServiceAccountResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.UpdateServiceAccount")
	defer span.End()

	if req.Msg.GetServiceAccount() == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service account is required"))
	} else if req.Msg.GetServiceAccount().GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("service account id is required"))
	}

	original := &user.ServiceAccount{Id: req.Msg.GetServiceAccount().GetId()}
	_, err := srv.getEntity(ctx, original)
	if err != nil {
		return nil, err
	}

	// most fields are immutable, so we only update the ones that are allowed to be modified
	entity := proto.CloneOf(original)
	entity.Description = req.Msg.ServiceAccount.Description
	entity.NamespaceId = req.Msg.ServiceAccount.NamespaceId

	record, err := srv.putEntity(ctx, entity)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&configpb.UpdateServiceAccountResponse{
		ServiceAccount: userServiceAccountToConfigServiceAccount(record, entity),
	}), nil
}

func (srv *backendConfigServer) UpdateSettings(
	ctx context.Context,
	req *connect.Request[configpb.UpdateSettingsRequest],
) (*connect.Response[configpb.UpdateSettingsResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.UpdateSettings")
	defer span.End()

	entity := proto.CloneOf(req.Msg.GetSettings())
	if entity == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("settings are required"))
	}
	if entity.Id == nil {
		entity.Id = proto.String(GlobalSettingsID)
	}

	original := proto.CloneOf(entity)
	_, err := srv.getEntity(ctx, original)
	if storage.IsNotFound(err) {
		original.CreatedAt = timestamppb.Now()
	} else if err != nil {
		return nil, err
	}

	entity.CreatedAt = original.CreatedAt
	record, err := srv.putEntity(ctx, entity)
	if err != nil {
		return nil, err
	}
	entity.ModifiedAt = record.ModifiedAt

	return connect.NewResponse(&configpb.UpdateSettingsResponse{
		Settings: entity,
	}), nil
}

func (srv *backendConfigServer) createEntity(
	ctx context.Context,
	entity proto.Message,
	idPtr **string,
) (*databrokerpb.Record, error) {
	recordType := grpcutil.GetTypeURL(entity)
	recordTypeName := string(entity.ProtoReflect().Descriptor().Name())

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error getting storage backend (type=%s): %w", recordTypeName, err))
	}

	// if no id was passed generate a uuid,
	// otherwise make sure an entity with this id doesn't already exist
	if *idPtr == nil {
		*idPtr = proto.String(uuid.NewString())
	} else {
		_, err := db.Get(ctx, recordType, **idPtr)
		if err == nil {
			return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("%s already exists (id=%s)", recordTypeName, **idPtr))
		} else if !storage.IsNotFound(err) {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error checking if %s exists (id=%s): %w", recordTypeName, **idPtr, err))
		}
	}

	data, err := anypb.New(entity)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error converting %s to any (id=%s): %w", recordTypeName, **idPtr, err))
	}

	records := []*databrokerpb.Record{{
		Type: recordType,
		Id:   **idPtr,
		Data: data,
	}}
	_, err = db.Put(ctx, records)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error creating %s (id=%s): %w", recordTypeName, **idPtr, err))
	}

	return records[0], nil
}

func (srv *backendConfigServer) deleteEntity(
	ctx context.Context,
	entity interface {
		proto.Message
		GetId() string
	},
) error {
	recordType := grpcutil.GetTypeURL(entity)
	recordTypeName := string(entity.ProtoReflect().Descriptor().Name())

	db, err := srv.getBackend(ctx)
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("error getting storage backend (type=%s id=%s): %w", recordTypeName, entity.GetId(), err))
	}

	record, err := db.Get(ctx, recordType, entity.GetId())
	if storage.IsNotFound(err) {
		return nil
	} else if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("error retrieving %s (id=%s): %w", recordTypeName, entity.GetId(), err))
	}
	record.DeletedAt = timestamppb.Now()

	_, err = db.Put(ctx, []*databrokerpb.Record{record})
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("error deleting %s (id=%s): %w", recordTypeName, entity.GetId(), err))
	}

	return nil
}

func (srv *backendConfigServer) getEntity(
	ctx context.Context,
	entity interface {
		proto.Message
		GetId() string
	},
) (*databrokerpb.Record, error) {
	recordType := grpcutil.GetTypeURL(entity)
	recordTypeName := string(entity.ProtoReflect().Descriptor().Name())

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error getting storage backend (type=%s id=%s): %w", recordTypeName, entity.GetId(), err))
	}

	record, err := db.Get(ctx, recordType, entity.GetId())
	if storage.IsNotFound(err) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("%s not found (id=%s): %w", recordTypeName, entity.GetId(), err))
	} else if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error getting %s (id=%s): %w", recordTypeName, entity.GetId(), err))
	}

	err = record.Data.UnmarshalTo(entity)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error unmarshaling %s (id=%s): %w", recordTypeName, entity.GetId(), err))
	}

	return record, nil
}

func (srv *backendConfigServer) putEntity(
	ctx context.Context,
	entity interface {
		proto.Message
		GetId() string
	},
) (*databrokerpb.Record, error) {
	recordType := grpcutil.GetTypeURL(entity)
	recordTypeName := string(entity.ProtoReflect().Descriptor().Name())

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	data, err := anypb.New(entity)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error converting %s to any (id=%s): %w", recordTypeName, entity.GetId(), err))
	}

	records := []*databrokerpb.Record{{
		Type: recordType,
		Id:   entity.GetId(),
		Data: data,
	}}
	_, err = db.Put(ctx, records)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error updating %s (id=%s): %w", recordTypeName, entity.GetId(), err))
	}

	return records[0], nil
}

func listRecords[T any, TMsg interface {
	*T
	proto.Message
}](
	ctx context.Context,
	srv *backendConfigServer,
	recordType string,
	offset *uint64,
	limit *uint64,
	filter *structpb.Struct,
	orderBy *string,
) (entities []*databrokerpb.Record, total uint64, err error) {
	expr, err := storage.FilterExpressionFromStruct(filter)
	if err != nil {
		return nil, 0, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid filter expression: %w", err))
	}

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, 0, connect.NewError(connect.CodeInternal, err)
	}

	streamCtx, cancelStream := context.WithCancel(ctx)
	defer cancelStream()

	_, _, seq, err := db.SyncLatest(streamCtx, recordType, expr)
	if err != nil {
		return nil, 0, connect.NewError(connect.CodeInternal, err)
	}

	var records []*databrokerpb.Record
	for record, err := range seq {
		if err != nil {
			return nil, 0, connect.NewError(connect.CodeInternal, err)
		}
		records = append(records, record)
	}
	total = uint64(len(records))

	err = sortRecords[T, TMsg](records, orderBy)
	if err != nil {
		return nil, 0, err
	}

	if offset != nil {
		if *offset > uint64(len(records)) {
			records = nil
		} else {
			records = records[*offset:]
		}
	}

	if limit != nil {
		if *limit < uint64(len(records)) {
			records = records[:*limit]
		}
	}

	return records, total, nil
}

func sortRecords[T any, TMsg interface {
	*T
	proto.Message
}](
	records []*databrokerpb.Record,
	orderBy *string,
) error {
	// no order by, just leave the slice as-is
	if orderBy == nil {
		return nil
	}

	var compares []protoutil.CompareFunc[TMsg]
	for _, o := range storage.OrderByFromString(*orderBy) {
		m := &fieldmaskpb.FieldMask{}
		m.Paths = strings.Split(o.Field, ".")
		c, err := protoutil.CompareFuncForFieldMask[T, TMsg](m)
		if err != nil {
			return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("invalid order by %s: %w", o.Field, err))
		}
		if !o.Ascending {
			invert := c
			c = func(x, y TMsg) int {
				return -1 * invert(x, y)
			}
		}
		compares = append(compares, c)
	}

	slices.SortStableFunc(records, func(x, y *databrokerpb.Record) int {
		var xt, yt T
		xErr := x.Data.UnmarshalTo(TMsg(&xt))
		yErr := y.Data.UnmarshalTo(TMsg(&yt))
		switch {
		case xErr != nil && yErr != nil:
			return 0
		case xErr != nil:
			return 1
		case yErr != nil:
			return -1
		}

		for _, c := range compares {
			v := c(TMsg(&xt), TMsg(&yt))
			if v != 0 {
				return v
			}
		}
		return 0
	})

	return nil
}

func userServiceAccountToConfigServiceAccount(record *databrokerpb.Record, serviceAccount *user.ServiceAccount) *configpb.ServiceAccount {
	var userID *string
	if serviceAccount.UserId != "" {
		userID = proto.String(serviceAccount.UserId)
	}
	return &configpb.ServiceAccount{
		AccessedAt:   serviceAccount.AccessedAt,
		CreatedAt:    serviceAccount.IssuedAt,
		Description:  serviceAccount.Description,
		ExpiresAt:    serviceAccount.ExpiresAt,
		Id:           proto.String(serviceAccount.Id),
		ModifiedAt:   record.ModifiedAt,
		NamespaceId:  serviceAccount.NamespaceId,
		OriginatorId: nil,
		UserId:       userID,
	}
}
