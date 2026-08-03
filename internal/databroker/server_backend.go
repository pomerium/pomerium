package databroker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"iter"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/durationpb"
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
	sharedKey               []byte

	stopWG  sync.WaitGroup
	stopCtx context.Context
	stop    context.CancelCauseFunc

	*backendConfigServer
}

// NewBackendServer creates a new Server using a storage backend.
func NewBackendServer(tracerProvider oteltrace.TracerProvider) Server {
	tracer := tracerProvider.Tracer(trace.PomeriumCoreTracer)
	srv := &backendServer{
		tracerProvider: tracerProvider,
		tracer:         tracer,
		storageType:    config.StorageInMemoryName,
	}
	srv.backendConfigServer = &backendConfigServer{
		backendServer: srv,
	}

	srv.stopCtx, srv.stop = context.WithCancelCause(context.Background())
	srv.stopWG.Go(func() {
		srv.periodicallyClean()
	})
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
		Msg("databroker/backend: acquire lease")

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
		Msg("databroker/backend: clearing all records")

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
		Msg("databroker/backend: get")

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
		Msg("databroker/backend: query")

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
			Msg("databroker/backend: put")
	} else {
		var recordType string
		for _, record := range records {
			recordType = record.GetType()
		}
		log.Ctx(ctx).Debug().
			Int("record-count", len(records)).
			Str("record-type", recordType).
			Msg("databroker/backend: put")
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
			Msg("databroker/backend: patch")
	} else {
		var recordType string
		for _, record := range records {
			recordType = record.GetType()
		}
		log.Ctx(ctx).Debug().
			Int("record-count", len(records)).
			Str("record-type", recordType).
			Msg("databroker/backend: patch")
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
		Msg("databroker/backend: release lease")

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
		Msg("databroker/backend: renew lease")

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

// GetOptions gets the options for a type in the databroker.
func (srv *backendServer) GetOptions(ctx context.Context, req *databrokerpb.GetOptionsRequest) (*databrokerpb.GetOptionsResponse, error) {
	if req.GetType() == "" {
		return nil, status.Error(codes.InvalidArgument, "options req type is empty")
	}

	backend, err := srv.getBackend(ctx)
	if err != nil {
		return nil, err
	}
	opts, err := backend.GetOptions(ctx, req.GetType())
	if err != nil {
		return nil, err
	}
	return &databrokerpb.GetOptionsResponse{
		Options: opts,
	}, nil
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
		Msg("databroker/backend: sync")

	backend, err := srv.getBackend(ctx)
	if err != nil {
		return err
	}

	wait := true
	if req.Wait != nil {
		wait = *req.Wait
	}

	seq := backend.Sync(ctx, req.GetType(), req.GetServerVersion(), req.GetRecordVersion(), wait)
	next, stop := iter.Pull2(seq)
	defer stop()
	_, err, ok := next()
	if !ok {
		return status.Error(codes.Internal, "sync never returned a first message")
	}
	if err != nil {
		return err
	}
	// FIXME: this only syncs the databroker options once per stream...
	// We need to either periodically poll and compute changes or implement SyncOptions()
	// on storage backends.
	if req.GetType() == "" {
		if err := srv.syncOptionsAll(ctx, backend, stream); err != nil {
			return err
		}
	} else {
		if err := srv.syncOptionsByType(ctx, req.GetType(), backend, stream); err != nil {
			return err
		}
	}
	for {
		record, err, ok := next()
		if !ok {
			break
		}
		if err != nil {
			return err
		}
		sendErr := stream.Send(&databrokerpb.SyncResponse{
			Response: &databrokerpb.SyncResponse_Record{
				Record: record,
			},
		})
		if sendErr != nil {
			return sendErr
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
		Msg("databroker/backend: sync latest")

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

	if req.GetType() == "" {
		if err := srv.syncLatestOptionsAll(ctx, backend, stream); err != nil {
			return err
		}
	} else {
		if err := srv.syncLatestOptionsByType(ctx, req.GetType(), backend, stream); err != nil {
			return err
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

func (srv *backendServer) syncLatestOptionsAll(ctx context.Context, backend storage.Backend, stream databrokerpb.DataBrokerService_SyncLatestServer) error {
	allTypes, err := backend.ListTypes(ctx)
	if err != nil {
		return err
	}

	for _, typ := range allTypes {
		if err := srv.syncLatestOptionsByType(ctx, typ, backend, stream); err != nil {
			return err
		}
	}
	return nil
}

func (srv *backendServer) syncOptionsAll(ctx context.Context, backend storage.Backend, stream databrokerpb.DataBrokerService_SyncServer) error {
	allTypes, err := backend.ListTypes(ctx)
	if err != nil {
		return err
	}

	for _, typ := range allTypes {
		if err := srv.syncOptionsByType(ctx, typ, backend, stream); err != nil {
			return err
		}
	}
	return nil
}

func (srv *backendServer) syncLatestOptionsByType(ctx context.Context, typeURL string, backend storage.Backend, stream databrokerpb.DataBrokerService_SyncLatestServer) error {
	opts, err := backend.GetOptions(ctx, typeURL)
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		return nil
	}
	if err != nil {
		return err
	}

	return stream.Send(&databrokerpb.SyncLatestResponse{
		Response: &databrokerpb.SyncLatestResponse_Options{
			Options: &databrokerpb.TypedOptions{
				TypeURL: typeURL,
				Options: opts,
			},
		},
	})
}

func (srv *backendServer) syncOptionsByType(ctx context.Context, typeURL string, backend storage.Backend, stream databrokerpb.DataBrokerService_SyncServer) error {
	opts, err := backend.GetOptions(ctx, typeURL)
	if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
		return nil
	}
	if err != nil {
		return err
	}

	return stream.Send(&databrokerpb.SyncResponse{
		Response: &databrokerpb.SyncResponse_Options{
			Options: &databrokerpb.TypedOptions{
				TypeURL: typeURL,
				Options: opts,
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
		log.Ctx(ctx).Error().Err(err).Msg("databroker/backend: error reading databroker storage connection string")
		return
	}

	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("databroker/backend: error reading shared key")
		return
	}

	// nothing changed
	if srv.storageType == storageType &&
		srv.storageConnectionString == storageConnectionString &&
		bytes.Equal(srv.sharedKey, sharedKey) {
		return
	}

	// set the options and close any backends so they are re-initialized
	srv.storageType = storageType
	srv.storageConnectionString = storageConnectionString
	srv.sharedKey = sharedKey

	if srv.backend != nil {
		err := srv.backend.Close()
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker/backend: error closing backend")
		}
		srv.backend = nil

		// clear the global cache
		storage.GlobalCache.InvalidateAll()
	}

	if srv.registry != nil {
		err := srv.registry.Close()
		if err != nil {
			log.Ctx(ctx).Error().Err(err).Msg("databroker/backend: error closing registry")
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
		Ttl:             durationpb.New(15 * time.Minute),
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

	if err := backend.SetOptions(ctx, "type.googleapis.com/oauth21.UpstreamMCPToken", &databrokerpb.Options{
		IndexableFields: []string{
			"user_id",
			"route_id",
		},
	}); err != nil {
		return err
	}

	if err := backend.SetOptions(ctx, "type.googleapis.com/oauth21.PendingUpstreamAuth", &databrokerpb.Options{
		IndexableFields: []string{
			"state_id",
		},
		Ttl: durationpb.New(15 * time.Minute),
	}); err != nil {
		return err
	}

	return nil
}

func (srv *backendServer) newBackendLocked(ctx context.Context) (storage.Backend, error) {
	switch srv.storageType {
	case config.StorageFileName:
		log.Ctx(ctx).Info().Msg("databroker/backend: initializing new file store")
		return file.New(srv.tracerProvider, srv.storageConnectionString, file.WithMetricAttributes(srv.storageMetricAttributes...)), nil
	case config.StorageInMemoryName:
		log.Ctx(ctx).Info().Msg("databroker/backend: initializing new in-memory store")
		return inmemory.New(srv.tracerProvider), nil
	case config.StoragePostgresName:
		log.Ctx(ctx).Info().Msg("databroker/backend: initializing new postgres store")
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
			recordTTLs := srv.buildRecordTTLs(backend)
			err := backend.Clean(srv.stopCtx, storage.CleanOptions{
				RemoveRecordChangesBefore: time.Now().Add(-expiry),
				RecordTTLs:                recordTTLs,
			})
			if err != nil {
				log.Ctx(srv.stopCtx).Error().Err(err).Msg("databroker/backend: error during periodic cleanup")
			}
		}

		select {
		case <-srv.stopCtx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (srv *backendServer) buildRecordTTLs(backend storage.Backend) map[string]time.Duration {
	types, err := backend.ListTypes(srv.stopCtx)
	if err != nil {
		log.Ctx(srv.stopCtx).Error().Err(err).Msg("databroker/backend: error listing types for TTL cleanup")
		return nil
	}

	var ttls map[string]time.Duration
	for _, recordType := range types {
		opts, err := backend.GetOptions(srv.stopCtx, recordType)
		if st, ok := status.FromError(err); ok && st.Code() == codes.NotFound {
			continue
		} else if err != nil {
			log.Ctx(srv.stopCtx).Error().Err(err).Str("record_type", recordType).
				Msg("databroker/backend: error getting options for TTL cleanup")
			continue
		}
		if opts.GetTtl() != nil && opts.GetTtl().AsDuration() > 0 {
			if ttls == nil {
				ttls = make(map[string]time.Duration)
			}
			ttls[recordType] = opts.GetTtl().AsDuration()
		}
	}
	return ttls
}

// TODO: this should be much longer and callers should probably set their own transaction deadlines.
// var rather than const so tests can shorten it.
var transactionMaxDuration = time.Minute

func (srv *backendServer) Transaction(stream grpc.BidiStreamingServer[databrokerpb.TransactionStreamRequest, databrokerpb.TransactionStreamResponse]) error {
	ctx, span := srv.tracer.Start(stream.Context(), "databroker.grpc.Transaction")
	defer span.End()

	ctx, cancel := context.WithTimeout(ctx, transactionMaxDuration)
	defer cancel()

	db, err := srv.getBackend(ctx)
	if err != nil {
		return err
	}

	recv := newTransactionReceiver(ctx, stream)
	defer recv.stop()

	begin, err := recv.next()
	if err != nil {
		return err
	}
	if begin.GetBegin() == nil {
		return status.Error(codes.InvalidArgument, "the first message of a transaction must be begin")
	}

	changed, shared, err := db.DoTransaction(ctx, begin.GetBegin().GetKey(), func(tx storage.Transaction) error {
		// the ack tells the client it was not suppressed, so it knows to submit
		err := stream.Send(&databrokerpb.TransactionStreamResponse{
			Sequence: begin.GetSequence(),
			Message: &databrokerpb.TransactionStreamResponse_Begin{
				Begin: new(databrokerpb.BeginTransactionResponse),
			},
		})
		if err != nil {
			return err
		}

		for {
			req, err := recv.next()
			if err != nil {
				return err
			}
			switch {
			case req.GetCommit() != nil:
				return nil
			case req.GetOperation() != nil:
				res, err := tx.Submit(req.GetOperation())
				if err != nil {
					return err
				}
				err = stream.Send(&databrokerpb.TransactionStreamResponse{
					Sequence: req.GetSequence(),
					Message:  &databrokerpb.TransactionStreamResponse_Operation{Operation: res},
				})
				if err != nil {
					return err
				}
			default:
				return status.Error(codes.InvalidArgument, "expected an operation or commit message")
			}
		}
	})
	if err != nil {
		return err
	}

	return stream.Send(&databrokerpb.TransactionStreamResponse{
		Message: &databrokerpb.TransactionStreamResponse_Commit{
			Commit: &databrokerpb.CommitTransactionResponse{Shared: shared, Records: changed},
		},
	})
}

// transactionReceiver reads from the stream on a goroutine so an idle timeout can
// interrupt a blocking Recv, which gRPC only unblocks when the handler returns.
type transactionReceiver struct {
	ctx  context.Context
	msgs chan *databrokerpb.TransactionStreamRequest
	errs chan error
	done chan struct{}
}

func newTransactionReceiver(
	ctx context.Context,
	stream grpc.BidiStreamingServer[databrokerpb.TransactionStreamRequest, databrokerpb.TransactionStreamResponse],
) *transactionReceiver {
	recv := &transactionReceiver{
		ctx:  ctx,
		msgs: make(chan *databrokerpb.TransactionStreamRequest),
		errs: make(chan error, 1),
		done: make(chan struct{}),
	}
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				recv.errs <- err
				return
			}
			select {
			case recv.msgs <- msg:
			case <-recv.done:
				return
			}
		}
	}()
	return recv
}

func (recv *transactionReceiver) next() (*databrokerpb.TransactionStreamRequest, error) {
	select {
	case msg := <-recv.msgs:
		return msg, nil
	case err := <-recv.errs:
		return nil, err
	case <-recv.ctx.Done():
		if errors.Is(recv.ctx.Err(), context.DeadlineExceeded) {
			return nil, status.Error(codes.DeadlineExceeded, "transaction deadline exceeded")
		}
		return nil, context.Cause(recv.ctx)
	}
}

func (recv *transactionReceiver) stop() {
	close(recv.done)
}
