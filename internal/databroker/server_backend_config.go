package databroker

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

// GlobalSettingsID is the default global settings id if none is provided.
const GlobalSettingsID = "78408adf-56e4-41d0-af6a-ca1b2d8d2cb6"

type backendConfigServer struct {
	*backendServer
}

func (srv *backendServer) CreateKeyPair(
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

func (srv *backendServer) CreatePolicy(
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

func (srv *backendServer) CreateRoute(
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

func (srv *backendConfigServer) DeleteKeyPair(
	ctx context.Context,
	req *connect.Request[configpb.DeleteKeyPairRequest],
) (*connect.Response[configpb.DeleteKeyPairResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.DeleteKeyPair")
	defer span.End()

	if req.Msg.GetId() == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("key pair id is required"))
	}

	keyPair := &configpb.KeyPair{Id: proto.String(req.Msg.GetId())}
	err := srv.deleteEntity(ctx, keyPair)
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

	keyPair := &configpb.Policy{Id: proto.String(req.Msg.GetId())}
	err := srv.deleteEntity(ctx, keyPair)
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

	keyPair := &configpb.Route{Id: proto.String(req.Msg.GetId())}
	err := srv.deleteEntity(ctx, keyPair)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(&configpb.DeleteRouteResponse{}), nil
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

func (srv *backendServer) GetPolicy(
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

func (srv *backendServer) GetRoute(
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

func (srv *backendServer) GetSettings(
	ctx context.Context,
	req *connect.Request[configpb.GetSettingsRequest],
) (*connect.Response[configpb.GetSettingsResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.GetSettings")
	defer span.End()

	id := req.Msg.GetId()
	if id == "" {
		id = GlobalSettingsID
	}

	entity := &configpb.Settings{
		Id: proto.String(id),
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

func (srv *backendServer) ListKeyPairs(
	ctx context.Context,
	req *connect.Request[configpb.ListKeyPairsRequest],
) (*connect.Response[configpb.ListKeyPairsResponse], error) {
	recordType := grpcutil.GetTypeURL(new(configpb.KeyPair))

	records, totalCount, err := srv.listRecords(ctx, recordType,
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
	}

	return connect.NewResponse(&configpb.ListKeyPairsResponse{
		KeyPairs:   entities,
		TotalCount: totalCount,
	}), nil
}

func (srv *backendServer) ListPolicies(
	ctx context.Context,
	req *connect.Request[configpb.ListPoliciesRequest],
) (*connect.Response[configpb.ListPoliciesResponse], error) {
	recordType := grpcutil.GetTypeURL(new(configpb.Policy))

	records, totalCount, err := srv.listRecords(ctx, recordType,
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
	}

	return connect.NewResponse(&configpb.ListPoliciesResponse{
		Policies:   entities,
		TotalCount: totalCount,
	}), nil
}

func (srv *backendServer) ListRoutes(
	ctx context.Context,
	req *connect.Request[configpb.ListRoutesRequest],
) (*connect.Response[configpb.ListRoutesResponse], error) {
	recordType := grpcutil.GetTypeURL(new(configpb.Route))

	records, totalCount, err := srv.listRecords(ctx, recordType,
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
	}

	return connect.NewResponse(&configpb.ListRoutesResponse{
		Routes:     entities,
		TotalCount: totalCount,
	}), nil
}

func (srv *backendServer) ListSettings(
	ctx context.Context,
	req *connect.Request[configpb.ListSettingsRequest],
) (*connect.Response[configpb.ListSettingsResponse], error) {
	recordType := grpcutil.GetTypeURL(new(configpb.Settings))

	records, totalCount, err := srv.listRecords(ctx, recordType,
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
	}

	return connect.NewResponse(&configpb.ListSettingsResponse{
		Settings:   entities,
		TotalCount: totalCount,
	}), nil
}

func (srv *backendServer) UpdateKeyPair(
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

func (srv *backendServer) UpdatePolicy(
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

func (srv *backendServer) UpdateRoute(
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

func (srv *backendServer) UpdateSettings(
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

func (srv *backendServer) createEntity(
	ctx context.Context,
	entity proto.Message,
	idPtr **string,
) (*databrokerpb.Record, error) {
	recordType := grpcutil.GetTypeURL(entity)
	recordTypeName := string(entity.ProtoReflect().Descriptor().Name())

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	// if no id was passed generate a uuid,
	// otherwise make sure a key pair with this id doesn't already exist
	if *idPtr == nil {
		*idPtr = proto.String(uuid.NewString())
	} else {
		_, err := db.Get(ctx, recordType, **idPtr)
		if err == nil {
			return nil, connect.NewError(connect.CodeAlreadyExists, fmt.Errorf("%s already exists", recordTypeName))
		} else if !storage.IsNotFound(err) {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error checking if %s exists: %w", recordTypeName, err))
		}
	}

	data, err := anypb.New(entity)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error converting %s to any: %w", recordTypeName, err))
	}

	records := []*databrokerpb.Record{{
		Id:   **idPtr,
		Type: recordType,
		Data: data,
	}}

	_, err = db.Put(ctx, records)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error creating %s: %w", recordTypeName, err))
	}

	return records[0], nil
}

func (srv *backendServer) deleteEntity(
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
		return connect.NewError(connect.CodeInternal, err)
	}

	record, err := db.Get(ctx, recordType, entity.GetId())
	if storage.IsNotFound(err) {
		return nil
	} else if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("error retrieving %s: %w", recordTypeName, err))
	}
	record.DeletedAt = timestamppb.Now()

	_, err = db.Put(ctx, []*databrokerpb.Record{record})
	if err != nil {
		return connect.NewError(connect.CodeInternal, fmt.Errorf("error deleting %s: %w", recordTypeName, err))
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
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	record, err := db.Get(ctx, recordType, entity.GetId())
	if storage.IsNotFound(err) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("%s not found: %w", recordTypeName, err))
	} else if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	err = record.Data.UnmarshalTo(entity)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	return record, nil
}

func (srv *backendServer) listRecords(
	ctx context.Context,
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

	if orderBy != nil {
		return nil, 0, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("order_by is not currently implemented"))
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

	return nil, total, nil
}

func (srv *backendServer) putEntity(
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
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error converting %s to any: %w", recordTypeName, err))
	}

	records := []*databrokerpb.Record{{
		Id:   entity.GetId(),
		Type: recordType,
		Data: data,
	}}
	_, err = db.Put(ctx, records)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("error updating %s: %w", recordTypeName, err))
	}

	return records[0], nil
}
