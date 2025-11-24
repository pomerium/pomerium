package databroker

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/registry"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/file"
	"github.com/pomerium/pomerium/pkg/storage/inmemory"
	"github.com/pomerium/pomerium/pkg/storage/postgres"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

type backendServer struct {
	tracerProvider oteltrace.TracerProvider
	tracer         oteltrace.Tracer

	mu                      sync.RWMutex
	backend                 storage.Backend
	registry                registry.Interface
	storageType             string
	storageConnectionString string
	storageMetricAttributes []attribute.KeyValue

	stopWG  sync.WaitGroup
	stopCtx context.Context
	stop    context.CancelCauseFunc
}

// NewBackendServer creates a new Server using a storage backend.
func NewBackendServer(tracerProvider oteltrace.TracerProvider) Server {
	tracer := tracerProvider.Tracer(trace.PomeriumCoreTracer)
	srv := &backendServer{
		tracerProvider: tracerProvider,
		tracer:         tracer,
		storageType:    config.StorageInMemoryName,
	}

	srv.stopCtx, srv.stop = context.WithCancelCause(context.Background())
	srv.stopWG.Add(1)
	go func() {
		defer srv.stopWG.Done()
		srv.periodicallyClean()
	}()
	return srv
}

func (srv *backendServer) SetStorageMetricAttributes(attrs ...attribute.KeyValue) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	srv.storageMetricAttributes = slices.Clone(attrs)
	if backend, ok := srv.backend.(interface {
		SetMetricAttributes(attrs ...attribute.KeyValue)
	}); ok {
		backend.SetMetricAttributes(attrs...)
	}
}

// AcquireLease acquires a lease.
func (srv *backendServer) AcquireLease(ctx context.Context, req *databrokerpb.AcquireLeaseRequest) (*databrokerpb.AcquireLeaseResponse, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.AcquireLease")
	defer span.End()
	log.Ctx(ctx).Debug().
		Str("name", req.GetName()).
		Dur("duration", req.GetDuration().AsDuration()).
		Msg("acquire lease")

	db, err := srv.getBackend(ctx)
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

	return &databrokerpb.AcquireLeaseResponse{
		Id: leaseID,
	}, nil
}

func (srv *backendServer) Clear(ctx context.Context, _ *emptypb.Empty) (*databrokerpb.ClearResponse, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.Clear")
	defer span.End()
	log.Ctx(ctx).Debug().
		Msg("clearing all records")

	backend, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	oldServerVersion, _, _, err := backend.Versions(ctx)
	if err != nil {
		return nil, err
	}

	err = backend.Clear(ctx)
	if err != nil {
		return nil, err
	}

	newServerVersion, _, _, err := backend.Versions(ctx)
	if err != nil {
		return nil, err
	}

	return &databrokerpb.ClearResponse{
		OldServerVersion: oldServerVersion,
		NewServerVersion: newServerVersion,
	}, nil
}

// Get gets a record from the in-memory list.
func (srv *backendServer) Get(ctx context.Context, req *databrokerpb.GetRequest) (*databrokerpb.GetResponse, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.Get")
	defer span.End()
	log.Ctx(ctx).Debug().
		Str("type", req.GetType()).
		Str("id", req.GetId()).
		Msg("get")

	db, err := srv.getBackend(ctx)
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
	return &databrokerpb.GetResponse{
		Record: record,
	}, nil
}

// GetCheckpoint gets the latest checkpoint.
func (srv *backendServer) GetCheckpoint(ctx context.Context, _ *databrokerpb.GetCheckpointRequest) (*databrokerpb.GetCheckpointResponse, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.GetCheckpoint")
	defer span.End()

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	serverVersion, recordVersion, err := db.GetCheckpoint(ctx)
	if err != nil {
		return nil, err
	}

	return &databrokerpb.GetCheckpointResponse{
		Checkpoint: &databrokerpb.Checkpoint{
			ServerVersion: serverVersion,
			RecordVersion: recordVersion,
		},
	}, nil
}

// ListTypes lists all the record types.
func (srv *backendServer) ListTypes(ctx context.Context, _ *emptypb.Empty) (*databrokerpb.ListTypesResponse, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.ListTypes")
	defer span.End()
	log.Ctx(ctx).Debug().Msg("list types")

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}
	types, err := db.ListTypes(ctx)
	if err != nil {
		return nil, err
	}
	return &databrokerpb.ListTypesResponse{Types: types}, nil
}

// Query queries for records.
func (srv *backendServer) Query(ctx context.Context, req *databrokerpb.QueryRequest) (*databrokerpb.QueryResponse, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.Query")
	defer span.End()
	log.Ctx(ctx).Debug().
		Str("type", req.GetType()).
		Str("query", req.GetQuery()).
		Int64("offset", req.GetOffset()).
		Int64("limit", req.GetLimit()).
		Interface("filter", req.GetFilter()).
		Msg("query")

	query := strings.ToLower(req.GetQuery())

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	expr, err := storage.FilterExpressionFromStruct(req.GetFilter())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid query filter: %v", err)
	}

	serverVersion, recordVersion, seq, err := db.SyncLatest(ctx, req.GetType(), expr)
	if err != nil {
		return nil, err
	}

	var filtered []*databrokerpb.Record
	for record, err := range seq {
		if err != nil {
			return nil, err
		}

		if query != "" && !storage.MatchAny(record.GetData(), query) {
			continue
		}

		filtered = append(filtered, record)
	}

	records, totalCount := databrokerpb.ApplyOffsetAndLimit(filtered, int(req.GetOffset()), int(req.GetLimit()))
	return &databrokerpb.QueryResponse{
		Records:       records,
		TotalCount:    int64(totalCount),
		ServerVersion: serverVersion,
		RecordVersion: recordVersion,
	}, nil
}

// Put updates an existing record or adds a new one.
func (srv *backendServer) Put(ctx context.Context, req *databrokerpb.PutRequest) (*databrokerpb.PutResponse, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.Put")
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

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	serverVersion, err := db.Put(ctx, records)
	if err != nil {
		return nil, err
	}
	res := &databrokerpb.PutResponse{
		ServerVersion: serverVersion,
		Records:       records,
	}

	return res, nil
}

// Patch updates specific fields of an existing record.
func (srv *backendServer) Patch(ctx context.Context, req *databrokerpb.PatchRequest) (*databrokerpb.PatchResponse, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.Patch")
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

	db, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	serverVersion, patchedRecords, err := db.Patch(ctx, records, req.GetFieldMask())
	if err != nil {
		return nil, err
	}
	res := &databrokerpb.PatchResponse{
		ServerVersion: serverVersion,
		Records:       patchedRecords,
	}

	return res, nil
}

// ReleaseLease releases a lease.
func (srv *backendServer) ReleaseLease(ctx context.Context, req *databrokerpb.ReleaseLeaseRequest) (*emptypb.Empty, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.ReleaseLease")
	defer span.End()
	log.Ctx(ctx).Trace().
		Str("name", req.GetName()).
		Str("id", req.GetId()).
		Msg("release lease")

	db, err := srv.getBackend(ctx)
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
func (srv *backendServer) RenewLease(ctx context.Context, req *databrokerpb.RenewLeaseRequest) (*emptypb.Empty, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.RenewLease")
	defer span.End()
	log.Ctx(ctx).Trace().
		Str("name", req.GetName()).
		Str("id", req.GetId()).
		Dur("duration", req.GetDuration().AsDuration()).
		Msg("renew lease")

	db, err := srv.getBackend(ctx)
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

// ServerInfo returns info about the databroker server.
func (srv *backendServer) ServerInfo(ctx context.Context, _ *emptypb.Empty) (*databrokerpb.ServerInfoResponse, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.ServerInfo")
	defer span.End()

	backend, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	serverVersion, earliestRecordVersion, latestRecordVersion, err := backend.Versions(ctx)
	if err != nil {
		return nil, err
	}

	res := new(databrokerpb.ServerInfoResponse)
	res.ServerVersion = serverVersion
	res.EarliestRecordVersion = earliestRecordVersion
	res.LatestRecordVersion = latestRecordVersion
	return res, nil
}

// SetCheckpoint sets the latest checkpoint.
func (srv *backendServer) SetCheckpoint(ctx context.Context, req *databrokerpb.SetCheckpointRequest) (*databrokerpb.SetCheckpointResponse, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.SetCheckpoint")
	defer span.End()

	backend, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}

	err = backend.SetCheckpoint(ctx, req.GetCheckpoint().GetServerVersion(), req.GetCheckpoint().GetRecordVersion())
	if err != nil {
		return nil, err
	}

	return new(databrokerpb.SetCheckpointResponse), nil
}

// SetOptions sets options for a type in the databroker.
func (srv *backendServer) SetOptions(ctx context.Context, req *databrokerpb.SetOptionsRequest) (*databrokerpb.SetOptionsResponse, error) {
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.SetOptions")
	defer span.End()

	backend, err := srv.getBackend(ctx)
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
	return &databrokerpb.SetOptionsResponse{
		Options: options,
	}, nil
}

// Sync streams updates for the given record type.
func (srv *backendServer) Sync(req *databrokerpb.SyncRequest, stream databrokerpb.DataBrokerService_SyncServer) error {
	ctx := stream.Context()
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.Sync")
	defer span.End()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	log.Ctx(ctx).
		Debug().
		Uint64("server_version", req.GetServerVersion()).
		Uint64("record_version", req.GetRecordVersion()).
		Msg("sync")

	backend, err := srv.getBackend(ctx)
	if err != nil {
		return err
	}

	wait := true
	if req.Wait != nil {
		wait = *req.Wait
	}
	seq := backend.Sync(ctx, req.GetType(), req.GetServerVersion(), req.GetRecordVersion(), wait)
	for record, err := range seq {
		if err != nil {
			return err
		}
		err = stream.Send(&databrokerpb.SyncResponse{
			Record: record,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

// SyncLatest returns the latest value of every record in the databroker as a stream of records.
func (srv *backendServer) SyncLatest(req *databrokerpb.SyncLatestRequest, stream databrokerpb.DataBrokerService_SyncLatestServer) error {
	ctx := stream.Context()
	ctx, span := srv.tracer.Start(ctx, "databroker.grpc.SyncLatest")
	defer span.End()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	log.Ctx(ctx).Debug().
		Str("type", req.GetType()).
		Msg("sync latest")

	backend, err := srv.getBackend(ctx)
	if err != nil {
		return err
	}

	serverVersion, recordVersion, seq, err := backend.SyncLatest(ctx, req.GetType(), nil)
	if err != nil {
		return err
	}

	for record, err := range seq {
		if err != nil {
			return err
		}

		if req.GetType() == "" || req.GetType() == record.GetType() {
			err = stream.Send(&databrokerpb.SyncLatestResponse{
				Response: &databrokerpb.SyncLatestResponse_Record{
					Record: record,
				},
			})
			if err != nil {
				return err
			}
		}
	}

	// always send the server version last in case there are no records
	return stream.Send(&databrokerpb.SyncLatestResponse{
		Response: &databrokerpb.SyncLatestResponse_Versions{
			Versions: &databrokerpb.Versions{
				ServerVersion:       serverVersion,
				LatestRecordVersion: recordVersion,
			},
		},
	})
}

func (srv *backendServer) Stop() {
	srv.stop(context.Canceled)
	srv.stopWG.Wait()
}

func (srv *backendServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	storageType := cfg.Options.DataBroker.StorageType
	if storageType == "" {
		storageType = config.StorageInMemoryName
	}
	storageConnectionString, err := cfg.Options.DataBroker.GetStorageConnectionString()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("databroker: error reading databroker storage connection string")
		return
	}

	// nothing changed
	if srv.storageType == storageType && srv.storageConnectionString == storageConnectionString {
		return
	}

	// set the options and close any backends so they are re-initialized
	srv.storageType = storageType
	srv.storageConnectionString = storageConnectionString

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

func (srv *backendServer) getBackend(ctx context.Context) (backend storage.Backend, err error) {
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
			backend, err = srv.newBackendAndSetupLocked(ctx)
			srv.backend = backend
		}
		srv.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return backend, nil
}

func (srv *backendServer) newBackendAndSetupLocked(ctx context.Context) (storage.Backend, error) {
	backend, err := srv.newBackendLocked(ctx)
	if err != nil {
		return nil, err
	}

	setupErr := srv.setupRequiredIndex(ctx, backend)
	return backend, setupErr
}

func (srv *backendServer) setupRequiredIndex(ctx context.Context, backend storage.Backend) error {
	reqCap := uint64(50000)
	if err := backend.SetOptions(ctx, "type.googleapis.com/session.SessionBindingRequest", &databrokerpb.Options{
		Capacity:        &reqCap,
		IndexableFields: []string{"key"},
	}); err != nil {
		return err
	}

	if err := backend.SetOptions(ctx, "type.googleapis.com/session.SessionBinding", &databrokerpb.Options{
		IndexableFields: []string{
			"session_id",
			"user_id",
		},
	}); err != nil {
		return err
	}

	if err := backend.SetOptions(ctx, "type.googleapis.com/session.IdentityBinding", &databrokerpb.Options{
		IndexableFields: []string{
			"user_id",
		},
	}); err != nil {
		return err
	}
	return nil
}

func (srv *backendServer) newBackendLocked(ctx context.Context) (storage.Backend, error) {
	switch srv.storageType {
	case config.StorageFileName:
		log.Ctx(ctx).Info().Msg("initializing new file store")
		return file.New(srv.tracerProvider, srv.storageConnectionString, file.WithMetricAttributes(srv.storageMetricAttributes...)), nil
	case config.StorageInMemoryName:
		log.Ctx(ctx).Info().Msg("initializing new in-memory store")
		return inmemory.New(), nil
	case config.StoragePostgresName:
		log.Ctx(ctx).Info().Msg("initializing new postgres store")
		// NB: the context passed to postgres.New here is a separate context scoped
		// to the lifetime of the server itself. 'ctx' may be a short-lived request
		// context, since the backend is lazy-initialized.
		return postgres.New(srv.stopCtx, srv.storageConnectionString, postgres.WithTracerProvider(srv.tracerProvider)), nil
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", srv.storageType)
	}
}

func (srv *backendServer) periodicallyClean() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	expiry := time.Hour

	for {
		srv.mu.Lock()
		backend := srv.backend
		srv.mu.Unlock()
		if backend != nil {
			err := backend.Clean(srv.stopCtx, storage.CleanOptions{
				RemoveRecordChangesBefore: time.Now().Add(-expiry),
			})
			if err != nil {
				log.Ctx(srv.stopCtx).Error().Err(err).Msg("databroker: error remove changes before cutoff")
			}
		}

		select {
		case <-srv.stopCtx.Done():
			return
		case <-ticker.C:
		}
	}
}
