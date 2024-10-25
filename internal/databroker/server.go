// Package databroker contains a data broker implementation.
package databroker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/registry"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/inmemory"
	"github.com/pomerium/pomerium/pkg/storage/postgres"
)

// Server implements the databroker service using an in memory database.
type Server struct {
	cfg *serverConfig

	mu       sync.RWMutex
	backend  storage.Backend
	registry registry.Interface
}

// New creates a new server.
func New(options ...ServerOption) *Server {
	srv := &Server{}
	srv.UpdateConfig(options...)
	return srv
}

// UpdateConfig updates the server with the new options.
func (srv *Server) UpdateConfig(options ...ServerOption) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	ctx := context.TODO()

	cfg := newServerConfig(options...)
	if cmp.Equal(cfg, srv.cfg, cmp.AllowUnexported(serverConfig{})) {
		log.Ctx(ctx).Debug().Msg("databroker: no changes detected, re-using existing DBs")
		return
	}
	srv.cfg = cfg

	if srv.backend != nil {
		err := srv.backend.Close()
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker: error closing backend")
		}
		srv.backend = nil
	}

	if srv.registry != nil {
		err := srv.registry.Close()
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker: error closing registry")
		}
		srv.registry = nil
	}
}

// AcquireLease acquires a lease.
func (srv *Server) AcquireLease(ctx context.Context, req *databroker.AcquireLeaseRequest) (*databroker.AcquireLeaseResponse, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.AcquireLease")
	defer span.End()
	log.Ctx(ctx).Debug().
		Str("name", req.GetName()).
		Dur("duration", req.GetDuration().AsDuration()).
		Msg("acquire lease")

	db, err := srv.getBackend()
	if err != nil {
		return nil, err
	}

	leaseID := uuid.NewString()
	acquired, err := db.Lease(ctx, req.GetName(), leaseID, req.GetDuration().AsDuration())
	if err != nil {
		return nil, err
	} else if !acquired {
		return nil, status.Error(codes.AlreadyExists, "lease is already taken")
	}

	return &databroker.AcquireLeaseResponse{
		Id: leaseID,
	}, nil
}

// Get gets a record from the in-memory list.
func (srv *Server) Get(ctx context.Context, req *databroker.GetRequest) (*databroker.GetResponse, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.Get")
	defer span.End()
	log.Ctx(ctx).Debug().
		Str("type", req.GetType()).
		Str("id", req.GetId()).
		Msg("get")

	db, err := srv.getBackend()
	if err != nil {
		return nil, err
	}
	record, err := db.Get(ctx, req.GetType(), req.GetId())
	switch {
	case errors.Is(err, storage.ErrNotFound):
		return nil, status.Error(codes.NotFound, "record not found")
	case err != nil:
		return nil, status.Error(codes.Internal, err.Error())
	case record.DeletedAt != nil:
		return nil, status.Error(codes.NotFound, "record not found")
	}
	return &databroker.GetResponse{
		Record: record,
	}, nil
}

// ListTypes lists all the record types.
func (srv *Server) ListTypes(ctx context.Context, _ *emptypb.Empty) (*databroker.ListTypesResponse, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.ListTypes")
	defer span.End()
	log.Ctx(ctx).Debug().Msg("list types")

	db, err := srv.getBackend()
	if err != nil {
		return nil, err
	}
	types, err := db.ListTypes(ctx)
	if err != nil {
		return nil, err
	}
	return &databroker.ListTypesResponse{Types: types}, nil
}

// Query queries for records.
func (srv *Server) Query(ctx context.Context, req *databroker.QueryRequest) (*databroker.QueryResponse, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.Query")
	defer span.End()
	log.Ctx(ctx).Debug().
		Str("type", req.GetType()).
		Str("query", req.GetQuery()).
		Int64("offset", req.GetOffset()).
		Int64("limit", req.GetLimit()).
		Interface("filter", req.GetFilter()).
		Msg("query")

	query := strings.ToLower(req.GetQuery())

	db, err := srv.getBackend()
	if err != nil {
		return nil, err
	}

	expr, err := storage.FilterExpressionFromStruct(req.GetFilter())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid query filter: %v", err)
	}

	serverVersion, recordVersion, stream, err := db.SyncLatest(ctx, req.GetType(), expr)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	var filtered []*databroker.Record
	for stream.Next(false) {
		record := stream.Record()

		if query != "" && !storage.MatchAny(record.GetData(), query) {
			continue
		}

		filtered = append(filtered, record)
	}
	if stream.Err() != nil {
		return nil, stream.Err()
	}

	records, totalCount := databroker.ApplyOffsetAndLimit(filtered, int(req.GetOffset()), int(req.GetLimit()))
	return &databroker.QueryResponse{
		Records:       records,
		TotalCount:    int64(totalCount),
		ServerVersion: serverVersion,
		RecordVersion: recordVersion,
	}, nil
}

// Put updates an existing record or adds a new one.
func (srv *Server) Put(ctx context.Context, req *databroker.PutRequest) (*databroker.PutResponse, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.Put")
	defer span.End()

	records := req.GetRecords()
	if len(records) == 1 {
		log.Ctx(ctx).Debug().
			Str("record-type", records[0].GetType()).
			Str("record-id", records[0].GetId()).
			Msg("put")
	} else {
		var recordType string
		for _, record := range records {
			recordType = record.GetType()
		}
		log.Ctx(ctx).Debug().
			Int("record-count", len(records)).
			Str("record-type", recordType).
			Msg("put")
	}

	db, err := srv.getBackend()
	if err != nil {
		return nil, err
	}

	serverVersion, err := db.Put(ctx, records)
	if err != nil {
		return nil, err
	}
	res := &databroker.PutResponse{
		ServerVersion: serverVersion,
		Records:       records,
	}

	return res, nil
}

// Patch updates specific fields of an existing record.
func (srv *Server) Patch(ctx context.Context, req *databroker.PatchRequest) (*databroker.PatchResponse, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.Patch")
	defer span.End()

	records := req.GetRecords()
	if len(records) == 1 {
		log.Ctx(ctx).Debug().
			Str("record-type", records[0].GetType()).
			Str("record-id", records[0].GetId()).
			Msg("patch")
	} else {
		var recordType string
		for _, record := range records {
			recordType = record.GetType()
		}
		log.Ctx(ctx).Debug().
			Int("record-count", len(records)).
			Str("record-type", recordType).
			Msg("patch")
	}

	db, err := srv.getBackend()
	if err != nil {
		return nil, err
	}

	serverVersion, patchedRecords, err := db.Patch(ctx, records, req.GetFieldMask())
	if err != nil {
		return nil, err
	}
	res := &databroker.PatchResponse{
		ServerVersion: serverVersion,
		Records:       patchedRecords,
	}

	return res, nil
}

// ReleaseLease releases a lease.
func (srv *Server) ReleaseLease(ctx context.Context, req *databroker.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.ReleaseLease")
	defer span.End()
	log.Ctx(ctx).Debug().
		Str("name", req.GetName()).
		Str("id", req.GetId()).
		Msg("release lease")

	db, err := srv.getBackend()
	if err != nil {
		return nil, err
	}

	_, err = db.Lease(ctx, req.GetName(), req.GetId(), -1)
	if err != nil {
		return nil, err
	}

	return new(emptypb.Empty), nil
}

// RenewLease releases a lease.
func (srv *Server) RenewLease(ctx context.Context, req *databroker.RenewLeaseRequest) (*emptypb.Empty, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.RenewLease")
	defer span.End()
	log.Ctx(ctx).Debug().
		Str("name", req.GetName()).
		Str("id", req.GetId()).
		Dur("duration", req.GetDuration().AsDuration()).
		Msg("renew lease")

	db, err := srv.getBackend()
	if err != nil {
		return nil, err
	}

	acquired, err := db.Lease(ctx, req.GetName(), req.GetId(), req.GetDuration().AsDuration())
	if err != nil {
		return nil, err
	} else if !acquired {
		return nil, status.Error(codes.AlreadyExists, "lease no longer held")
	}

	return new(emptypb.Empty), nil
}

// SetOptions sets options for a type in the databroker.
func (srv *Server) SetOptions(ctx context.Context, req *databroker.SetOptionsRequest) (*databroker.SetOptionsResponse, error) {
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.SetOptions")
	defer span.End()

	backend, err := srv.getBackend()
	if err != nil {
		return nil, err
	}
	err = backend.SetOptions(ctx, req.GetType(), req.GetOptions())
	if err != nil {
		return nil, err
	}
	options, err := backend.GetOptions(ctx, req.GetType())
	if err != nil {
		return nil, err
	}
	return &databroker.SetOptionsResponse{
		Options: options,
	}, nil
}

// Sync streams updates for the given record type.
func (srv *Server) Sync(req *databroker.SyncRequest, stream databroker.DataBrokerService_SyncServer) error {
	ctx := stream.Context()
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.Sync")
	defer span.End()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	log.Ctx(ctx).Debug().
		Uint64("server_version", req.GetServerVersion()).
		Uint64("record_version", req.GetRecordVersion()).
		Msg("sync")

	backend, err := srv.getBackend()
	if err != nil {
		return err
	}

	recordStream, err := backend.Sync(ctx, req.GetType(), req.GetServerVersion(), req.GetRecordVersion())
	if err != nil {
		return err
	}
	defer func() { _ = recordStream.Close() }()

	for recordStream.Next(true) {
		err = stream.Send(&databroker.SyncResponse{
			Record: recordStream.Record(),
		})
		if err != nil {
			return err
		}
	}

	return recordStream.Err()
}

// SyncLatest returns the latest value of every record in the databroker as a stream of records.
func (srv *Server) SyncLatest(req *databroker.SyncLatestRequest, stream databroker.DataBrokerService_SyncLatestServer) error {
	ctx := stream.Context()
	ctx, span := trace.StartSpan(ctx, "databroker.grpc.SyncLatest")
	defer span.End()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	log.Ctx(ctx).Debug().
		Str("type", req.GetType()).
		Msg("sync latest")

	backend, err := srv.getBackend()
	if err != nil {
		return err
	}

	serverVersion, recordVersion, recordStream, err := backend.SyncLatest(ctx, req.GetType(), nil)
	if err != nil {
		return err
	}

	for recordStream.Next(false) {
		record := recordStream.Record()
		if req.GetType() == "" || req.GetType() == record.GetType() {
			err = stream.Send(&databroker.SyncLatestResponse{
				Response: &databroker.SyncLatestResponse_Record{
					Record: record,
				},
			})
			if err != nil {
				return err
			}
		}
	}
	if recordStream.Err() != nil {
		return err
	}

	// always send the server version last in case there are no records
	return stream.Send(&databroker.SyncLatestResponse{
		Response: &databroker.SyncLatestResponse_Versions{
			Versions: &databroker.Versions{
				ServerVersion:       serverVersion,
				LatestRecordVersion: recordVersion,
			},
		},
	})
}

func (srv *Server) getBackend() (backend storage.Backend, err error) {
	// double-checked locking:
	// first try the read lock, then re-try with the write lock, and finally create a new backend if nil
	srv.mu.RLock()
	backend = srv.backend
	srv.mu.RUnlock()
	if backend == nil {
		srv.mu.Lock()
		backend = srv.backend
		var err error
		if backend == nil {
			backend, err = srv.newBackendLocked()
			srv.backend = backend
		}
		srv.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return backend, nil
}

func (srv *Server) newBackendLocked() (backend storage.Backend, err error) {
	ctx := context.Background()

	switch srv.cfg.storageType {
	case config.StorageInMemoryName:
		log.Ctx(ctx).Info().Msg("using in-memory store")
		return inmemory.New(), nil
	case config.StoragePostgresName:
		log.Ctx(ctx).Info().Msg("using postgres store")
		backend = postgres.New(srv.cfg.storageConnectionString)
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", srv.cfg.storageType)
	}
	return backend, nil
}
