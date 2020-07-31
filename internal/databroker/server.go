// Package databroker contains a data broker implementation.
package databroker

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/inmemory"
	"github.com/pomerium/pomerium/pkg/storage/redis"
)

const (
	recordTypeServerVersion = "server_version"
	serverVersionKey        = "version"
)

// Server implements the databroker service using an in memory database.
type Server struct {
	version string
	cfg     *serverConfig
	log     zerolog.Logger

	mu           sync.RWMutex
	byType       map[string]storage.Backend
	onTypechange *signal.Signal
}

// New creates a new server.
func New(options ...ServerOption) *Server {
	cfg := newServerConfig(options...)
	srv := &Server{
		version: uuid.New().String(),
		cfg:     cfg,
		log:     log.With().Str("service", "databroker").Logger(),

		byType:       make(map[string]storage.Backend),
		onTypechange: signal.New(),
	}
	srv.initVersion()

	go func() {
		ticker := time.NewTicker(cfg.deletePermanentlyAfter / 2)
		defer ticker.Stop()

		for range ticker.C {
			var recordTypes []string
			srv.mu.RLock()
			for recordType := range srv.byType {
				recordTypes = append(recordTypes, recordType)
			}
			srv.mu.RUnlock()

			for _, recordType := range recordTypes {
				db, err := srv.getDB(recordType)
				if err != nil {
					continue
				}
				db.ClearDeleted(context.Background(), time.Now().Add(-cfg.deletePermanentlyAfter))
			}
		}
	}()
	return srv
}

func (srv *Server) initVersion() {
	dbServerVersion, err := srv.getDB(recordTypeServerVersion)
	if err != nil {
		log.Error().Err(err).Msg("failed to init server version")
		return
	}

	// Get version from storage first.
	if r, _ := dbServerVersion.Get(context.Background(), serverVersionKey); r != nil {
		var sv databroker.ServerVersion
		if err := ptypes.UnmarshalAny(r.GetData(), &sv); err == nil {
			srv.log.Debug().Str("server_version", sv.Version).Msg("got db version from DB")
			srv.version = sv.Version
		}
		return
	}

	data, _ := ptypes.MarshalAny(&databroker.ServerVersion{Version: srv.version})
	if err := dbServerVersion.Put(context.Background(), serverVersionKey, data); err != nil {
		srv.log.Warn().Err(err).Msg("failed to save server version.")
	}
}

// Delete deletes a record from the in-memory list.
func (srv *Server) Delete(ctx context.Context, req *databroker.DeleteRequest) (*empty.Empty, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.Delete")
	defer span.End()
	srv.log.Info().
		Str("type", req.GetType()).
		Str("id", req.GetId()).
		Msg("delete")

	db, err := srv.getDB(req.GetType())
	if err != nil {
		return nil, err
	}

	if err := db.Delete(ctx, req.GetId()); err != nil {
		return nil, err
	}

	return new(empty.Empty), nil
}

// Get gets a record from the in-memory list.
func (srv *Server) Get(ctx context.Context, req *databroker.GetRequest) (*databroker.GetResponse, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.Get")
	defer span.End()
	srv.log.Info().
		Str("type", req.GetType()).
		Str("id", req.GetId()).
		Msg("get")

	db, err := srv.getDB(req.GetType())
	if err != nil {
		return nil, err
	}
	record, err := db.Get(ctx, req.GetId())
	if err != nil {
		return nil, status.Error(codes.NotFound, "record not found")
	}
	if record.DeletedAt != nil {
		return nil, status.Error(codes.NotFound, "record not found")
	}
	return &databroker.GetResponse{Record: record}, nil
}

// GetAll gets all the records from the in-memory list.
func (srv *Server) GetAll(ctx context.Context, req *databroker.GetAllRequest) (*databroker.GetAllResponse, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.GetAll")
	defer span.End()
	srv.log.Info().
		Str("type", req.GetType()).
		Msg("get all")

	db, err := srv.getDB(req.GetType())
	if err != nil {
		return nil, err
	}

	all, err := db.GetAll(ctx)
	if err != nil {
		return nil, err
	}

	if len(all) == 0 {
		return &databroker.GetAllResponse{ServerVersion: srv.version}, nil
	}

	var recordVersion string
	records := make([]*databroker.Record, 0, len(all))
	for _, record := range all {
		if record.GetVersion() > recordVersion {
			recordVersion = record.GetVersion()
		}
		if record.DeletedAt == nil {
			records = append(records, record)
		}
	}

	return &databroker.GetAllResponse{
		ServerVersion: srv.version,
		RecordVersion: recordVersion,
		Records:       records,
	}, nil
}

// Set updates a record in the in-memory list, or adds a new one.
func (srv *Server) Set(ctx context.Context, req *databroker.SetRequest) (*databroker.SetResponse, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.Set")
	defer span.End()
	srv.log.Info().
		Str("type", req.GetType()).
		Str("id", req.GetId()).
		Msg("set")

	db, err := srv.getDB(req.GetType())
	if err != nil {
		return nil, err
	}
	if err := db.Put(ctx, req.GetId(), req.GetData()); err != nil {
		return nil, err
	}
	record, err := db.Get(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &databroker.SetResponse{
		Record:        record,
		ServerVersion: srv.version,
	}, nil
}

func (srv *Server) doSync(ctx context.Context, recordVersion *string, db storage.Backend, stream databroker.DataBrokerService_SyncServer) error {
	updated, err := db.List(ctx, *recordVersion)
	if err != nil {
		return err
	}
	if len(updated) == 0 {
		return nil
	}
	sort.Slice(updated, func(i, j int) bool {
		return updated[i].Version < updated[j].Version
	})
	*recordVersion = updated[len(updated)-1].Version
	return stream.Send(&databroker.SyncResponse{
		ServerVersion: srv.version,
		Records:       updated,
	})
}

// Sync streams updates for the given record type.
func (srv *Server) Sync(req *databroker.SyncRequest, stream databroker.DataBrokerService_SyncServer) error {
	_, span := trace.StartSpan(stream.Context(), "databroker.grpc.Sync")
	defer span.End()
	srv.log.Info().
		Str("type", req.GetType()).
		Str("server_version", req.GetServerVersion()).
		Str("record_version", req.GetRecordVersion()).
		Msg("sync")

	recordVersion := req.GetRecordVersion()
	// reset record version if the server versions don't match
	if req.GetServerVersion() != srv.version {
		recordVersion = ""
		// send the new server version to the client
		err := stream.Send(&databroker.SyncResponse{
			ServerVersion: srv.version,
		})
		if err != nil {
			return err
		}
	}

	db, err := srv.getDB(req.GetType())
	if err != nil {
		return err
	}

	ctx := stream.Context()
	ch := db.Watch(ctx)

	// Do first sync, so we won't missed anything.
	if err := srv.doSync(ctx, &recordVersion, db, stream); err != nil {
		return err
	}

	for range ch {
		if err := srv.doSync(ctx, &recordVersion, db, stream); err != nil {
			return err
		}
	}
	return nil
}

// GetTypes returns all the known record types.
func (srv *Server) GetTypes(ctx context.Context, _ *emptypb.Empty) (*databroker.GetTypesResponse, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.GetTypes")
	defer span.End()
	var recordTypes []string
	srv.mu.RLock()
	for recordType := range srv.byType {
		recordTypes = append(recordTypes, recordType)
	}
	srv.mu.RUnlock()

	sort.Strings(recordTypes)
	return &databroker.GetTypesResponse{
		Types: recordTypes,
	}, nil
}

// SyncTypes synchronizes all the known record types.
func (srv *Server) SyncTypes(req *emptypb.Empty, stream databroker.DataBrokerService_SyncTypesServer) error {
	_, span := trace.StartSpan(stream.Context(), "databroker.grpc.SyncTypes")
	defer span.End()
	srv.log.Info().
		Msg("sync types")

	ch := srv.onTypechange.Bind()
	defer srv.onTypechange.Unbind(ch)

	var prev []string
	for {
		res, err := srv.GetTypes(stream.Context(), req)
		if err != nil {
			return err
		}

		if prev == nil || !reflect.DeepEqual(prev, res.Types) {
			err := stream.Send(res)
			if err != nil {
				return err
			}
			prev = res.Types
		}

		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ch:
		}
	}
}

func (srv *Server) getDB(recordType string) (storage.Backend, error) {
	// double-checked locking:
	// first try the read lock, then re-try with the write lock, and finally create a new db if nil
	srv.mu.RLock()
	db := srv.byType[recordType]
	srv.mu.RUnlock()
	if db == nil {
		srv.mu.Lock()
		db = srv.byType[recordType]
		var err error
		if db == nil {
			db, err = srv.newDB(recordType)
			srv.byType[recordType] = db
		}
		srv.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	return db, nil
}

func (srv *Server) newDB(recordType string) (db storage.Backend, err error) {
	switch srv.cfg.storageType {
	case config.StorageInMemoryName:
		return inmemory.NewDB(recordType, srv.cfg.btreeDegree), nil
	case config.StorageRedisName:
		db, err = redis.New(
			srv.cfg.storageConnectionString,
			recordType,
			int64(srv.cfg.deletePermanentlyAfter.Seconds()),
			redis.WithTLSConfig(srv.cfg.storageTLSConfig),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create new redis storage: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", srv.cfg.storageType)
	}
	if srv.cfg.secret != nil {
		db, err = storage.NewEncryptedBackend(srv.cfg.secret, db)
		if err != nil {
			return nil, err
		}
	}
	return db, nil
}
