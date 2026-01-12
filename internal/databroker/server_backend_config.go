package databroker

import (
	"context"
	"fmt"
	"math"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/storage"
)

func (srv *backendServer) CreateKeyPair(
	ctx context.Context,
	_ *connect.Request[configpb.CreateKeyPairRequest],
) (*connect.Response[configpb.CreateKeyPairResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.CreateKeyPair")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) CreateNamespace(
	ctx context.Context,
	req *connect.Request[configpb.CreateNamespaceRequest],
) (*connect.Response[configpb.CreateNamespaceResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.CreateNamespace")
	defer span.End()

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	namespace := proto.CloneOf(req.Msg.Namespace)
	if namespace == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("namespace is required"))
	}
	if namespace.Name == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("name is required"))
	}
	if namespace.ClusterId != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("a cluster namespace cannot be created directly"))
	}
	if namespace.Id != "" {
		if err := srv.checkRecordDoesNotExist(ctx, db, grpcutil.GetTypeURL(namespace), namespace.Id); err != nil {
			return nil, err
		}
	} else {
		namespace.Id = uuid.New().String()
	}
	namespace.CreatedAt = timestamppb.Now()
	namespace.ModifiedAt = nil

	data, err := anypb.New(namespace)
	if err != nil {
		return nil, err
	}
	records := []*databroker.Record{{
		Type: grpcutil.GetTypeURL(namespace),
		Id:   namespace.Id,
		Data: data,
	}}
	_, err = db.Put(ctx, records)
	if err != nil {
		return nil, fmt.Errorf("error creating namespace: %w", err)
	}

	namespace, err = recordToNamespace(records[0])
	if err != nil {
		return nil, fmt.Errorf("error converting databroker record to namespace: %w", err)
	}

	return connect.NewResponse(&configpb.CreateNamespaceResponse{
		Namespace: namespace,
	}), nil
}

func (srv *backendServer) CreatePolicy(
	ctx context.Context,
	_ *connect.Request[configpb.CreatePolicyRequest],
) (*connect.Response[configpb.CreatePolicyResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.CreatePolicy")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) CreateRoute(
	ctx context.Context,
	_ *connect.Request[configpb.CreateRouteRequest],
) (*connect.Response[configpb.CreateRouteResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.CreateRoute")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) DeleteKeyPair(
	ctx context.Context,
	_ *connect.Request[configpb.DeleteKeyPairRequest],
) (*connect.Response[configpb.DeleteKeyPairResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.DeleteKeyPair")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) DeleteNamespace(
	ctx context.Context,
	req *connect.Request[configpb.DeleteNamespaceRequest],
) (*connect.Response[configpb.DeleteNamespaceResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.DeleteNamespace")
	defer span.End()

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	if req.Msg.Id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("id is required"))
	}

	res, err := db.Get(ctx, grpcutil.GetTypeURL(new(configpb.Namespace)), req.Msg.Id)
	if storage.IsNotFound(err) {
		return connect.NewResponse(&configpb.DeleteNamespaceResponse{}), nil
	} else if err != nil {
		return nil, fmt.Errorf("error retrieving namespace: %w", err)
	}

	res.DeletedAt = timestamppb.Now()
	_, err = db.Put(ctx, []*databroker.Record{res})
	if err != nil {
		return nil, fmt.Errorf("error deleting namespace: %w", err)
	}

	return connect.NewResponse(&configpb.DeleteNamespaceResponse{}), nil
}

func (srv *backendServer) DeletePolicy(
	ctx context.Context,
	_ *connect.Request[configpb.DeletePolicyRequest],
) (*connect.Response[configpb.DeletePolicyResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.DeletePolicy")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) DeleteRoute(
	ctx context.Context,
	_ *connect.Request[configpb.DeleteRouteRequest],
) (*connect.Response[configpb.DeleteRouteResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.DeleteRoute")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) GetKeyPair(
	ctx context.Context,
	_ *connect.Request[configpb.GetKeyPairRequest],
) (*connect.Response[configpb.GetKeyPairResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.GetKeyPair")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) GetNamespace(
	ctx context.Context,
	req *connect.Request[configpb.GetNamespaceRequest],
) (*connect.Response[configpb.GetNamespaceResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.GetNamespace")
	defer span.End()

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	if req.Msg.Id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("id is required"))
	}

	res, err := db.Get(ctx, grpcutil.GetTypeURL(new(configpb.Namespace)), req.Msg.Id)
	if storage.IsNotFound(err) {
		return nil, connect.NewError(connect.CodeNotFound, fmt.Errorf("namespace not found"))
	} else if err != nil {
		return nil, fmt.Errorf("error retrieving namespace: %w", err)
	}

	namespace, err := recordToNamespace(res)
	if err != nil {
		return nil, fmt.Errorf("error converting databroker record to namespace: %w", err)
	}

	return connect.NewResponse(&configpb.GetNamespaceResponse{
		Namespace: namespace,
	}), nil
}

func (srv *backendServer) GetPolicy(
	ctx context.Context,
	_ *connect.Request[configpb.GetPolicyRequest],
) (*connect.Response[configpb.GetPolicyResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.GetPolicy")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) GetRoute(
	ctx context.Context,
	_ *connect.Request[configpb.GetRouteRequest],
) (*connect.Response[configpb.GetRouteResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.GetRoute")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) GetSettings(
	ctx context.Context,
	_ *connect.Request[configpb.GetSettingsRequest],
) (*connect.Response[configpb.GetSettingsResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.GetSettings")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) ListKeyPairs(
	ctx context.Context,
	_ *connect.Request[configpb.ListKeyPairsRequest],
) (*connect.Response[configpb.ListKeyPairsResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.ListKeyPairs")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) ListNamespaces(
	ctx context.Context,
	req *connect.Request[configpb.ListNamespacesRequest],
) (*connect.Response[configpb.ListNamespacesResponse], error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.connect.ListNamespaces")
	defer span.End()

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	namespaces, totalCount, err := listRecords(ctx, db,
		req.Msg.Filter, req.Msg.OrderBy,
		req.Msg.Offset, req.Msg.Limit,
		recordToNamespace)
	if err != nil {
		return nil, fmt.Errorf("error listing namespaces: %w", err)
	}

	return connect.NewResponse(&configpb.ListNamespacesResponse{
		Namespaces: namespaces,
		TotalCount: totalCount,
	}), nil
}

func (srv *backendServer) ListPolicies(
	ctx context.Context,
	_ *connect.Request[configpb.ListPoliciesRequest],
) (*connect.Response[configpb.ListPoliciesResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.ListPolicies")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) ListRoutes(
	ctx context.Context,
	_ *connect.Request[configpb.ListRoutesRequest],
) (*connect.Response[configpb.ListRoutesResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.ListRoutes")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) ListSettings(
	ctx context.Context,
	_ *connect.Request[configpb.ListSettingsRequest],
) (*connect.Response[configpb.ListSettingsResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.ListSettings")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) UpdateKeyPair(
	ctx context.Context,
	_ *connect.Request[configpb.UpdateKeyPairRequest],
) (*connect.Response[configpb.UpdateKeyPairResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.UpdateKeyPair")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) UpdateNamespace(
	ctx context.Context,
	_ *connect.Request[configpb.UpdateNamespaceRequest],
) (*connect.Response[configpb.UpdateNamespaceResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.UpdateNamespace")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) UpdatePolicy(
	ctx context.Context,
	_ *connect.Request[configpb.UpdatePolicyRequest],
) (*connect.Response[configpb.UpdatePolicyResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.UpdatePolicy")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) UpdateRoute(
	ctx context.Context,
	_ *connect.Request[configpb.UpdateRouteRequest],
) (*connect.Response[configpb.UpdateRouteResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.UpdateRoute")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) UpdateSettings(
	ctx context.Context,
	_ *connect.Request[configpb.UpdateSettingsRequest],
) (*connect.Response[configpb.UpdateSettingsResponse], error) {
	_, span := srv.tracer.Start(ctx, "databroker.connect.UpdateSettings")
	defer span.End()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("unimplemented"))
}

func (srv *backendServer) checkRecordDoesNotExist(ctx context.Context, backend storage.Backend, recordType, recordID string) error {
	_, err := backend.Get(ctx, recordType, recordID)
	if storage.IsNotFound(err) {
		return nil
	} else if err != nil {
		return err
	}

	return connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("record with type %s and id %s already exists", recordType, recordID))
}

func listRecords[T any, TMsg interface {
	*T
	proto.Message
}](
	ctx context.Context,
	backend storage.Backend,
	filter, orderBy *string,
	offset, limit *uint64,
	convert func(*databroker.Record) (TMsg, error),
) ([]TMsg, uint64, error) {
	if filter != nil {
		return nil, 0, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("filtering is not currently supported"))
	}
	if orderBy != nil {
		return nil, 0, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("sorting is not currently supported"))
	}

	_, _, seq, err := backend.SyncLatest(ctx, grpcutil.GetTypeURL(TMsg(new(T))), nil)
	if err != nil {
		return nil, 0, err
	}

	if offset == nil {
		offset = proto.Uint64(0)
	}
	if limit == nil {
		limit = proto.Uint64(math.MaxUint64)
	}

	var buf []TMsg
	idx := uint64(0)
	for record, err := range seq {
		if err != nil {
			return nil, 0, err
		}
		if idx >= *offset && idx-*offset < *limit {
			data, err := convert(record)
			if err != nil {
				return nil, 0, err
			}
			buf = append(buf, data)
		}
		idx++
	}

	return buf, idx, nil
}

func recordToNamespace(record *databroker.Record) (*configpb.Namespace, error) {
	namespace := new(configpb.Namespace)
	err := record.Data.UnmarshalTo(namespace)
	if err != nil {
		return nil, err
	}
	namespace.ModifiedAt = record.ModifiedAt
	return namespace, nil
}
