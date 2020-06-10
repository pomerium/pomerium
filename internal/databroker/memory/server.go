// Package memory contains an in-memory data broker implementation.
package memory

import (
	"context"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/internal/grpc/databroker"
	"github.com/pomerium/pomerium/internal/log"
)

// Server implements the databroker service using an in memory database.
type Server struct {
	version string
	cfg     *serverConfig
	log     zerolog.Logger

	mu       sync.RWMutex
	byType   map[string]*DB
	onchange *Signal
}

// New creates a new server.
func New(options ...ServerOption) *Server {
	cfg := newServerConfig(options...)
	srv := &Server{
		version: uuid.New().String(),
		cfg:     cfg,
		log:     log.With().Str("service", "databroker").Logger(),

		byType:   make(map[string]*DB),
		onchange: NewSignal(),
	}
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
				srv.getDB(recordType).ClearDeleted(time.Now().Add(-cfg.deletePermanentlyAfter))
			}
		}
	}()
	return srv
}

// Delete deletes a record from the in-memory list.
func (srv *Server) Delete(ctx context.Context, req *databroker.DeleteRequest) (*empty.Empty, error) {
	srv.log.Info().
		Str("type", req.GetType()).
		Str("id", req.GetId()).
		Msg("delete")

	defer srv.onchange.Broadcast()

	srv.getDB(req.GetType()).Delete(req.GetId())

	return new(empty.Empty), nil
}

// Get gets a record from the in-memory list.
func (srv *Server) Get(ctx context.Context, req *databroker.GetRequest) (*databroker.GetResponse, error) {
	srv.log.Info().
		Str("type", req.GetType()).
		Str("id", req.GetId()).
		Msg("get")

	record := srv.getDB(req.GetType()).Get(req.GetId())
	if record == nil {
		return nil, status.Error(codes.NotFound, "record not found")
	}
	return &databroker.GetResponse{Record: record}, nil
}

// GetAll gets all the records from the in-memory list.
func (srv *Server) GetAll(ctx context.Context, req *databroker.GetAllRequest) (*databroker.GetAllResponse, error) {
	srv.log.Info().
		Str("type", req.GetType()).
		Msg("get all")

	records := srv.getDB(req.GetType()).GetAll()
	var recordVersion string
	for _, record := range records {
		if record.GetVersion() > recordVersion {
			recordVersion = record.GetVersion()
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
	srv.log.Info().
		Str("type", req.GetType()).
		Str("id", req.GetId()).
		Msg("set")

	defer srv.onchange.Broadcast()

	db := srv.getDB(req.GetType())
	db.Set(req.GetId(), req.GetData())
	record := db.Get(req.GetId())

	return &databroker.SetResponse{
		Record: record,
	}, nil
}

// Sync streams updates for the given record type.
func (srv *Server) Sync(req *databroker.SyncRequest, stream databroker.DataBrokerService_SyncServer) error {
	srv.log.Info().
		Str("type", req.GetType()).
		Str("server_version", req.GetServerVersion()).
		Str("record_version", req.GetRecordVersion()).
		Msg("sync")

	recordVersion := req.GetRecordVersion()
	// reset record version if the server versions don't match
	if req.GetServerVersion() != srv.version {
		recordVersion = ""
	}

	db := srv.getDB(req.GetType())

	ch := srv.onchange.Bind()
	defer srv.onchange.Unbind(ch)
	for {
		updated := db.List(recordVersion)

		if len(updated) > 0 {
			sort.Slice(updated, func(i, j int) bool {
				return updated[i].Version < updated[j].Version
			})
			recordVersion = updated[len(updated)-1].Version
			err := stream.Send(&databroker.SyncResponse{
				ServerVersion: srv.version,
				Records:       updated,
			})
			if err != nil {
				return err
			}
		}

		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-ch:
		}
	}
}

// GetTypes returns all the known record types.
func (srv *Server) GetTypes(_ context.Context, _ *emptypb.Empty) (*databroker.GetTypesResponse, error) {
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
	srv.log.Info().
		Msg("sync types")

	ch := srv.onchange.Bind()
	defer srv.onchange.Unbind(ch)

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

func (srv *Server) getDB(recordType string) *DB {
	// double-checked locking:
	// first try the read lock, then re-try with the write lock, and finally create a new db if nil
	srv.mu.RLock()
	db := srv.byType[recordType]
	srv.mu.RUnlock()
	if db == nil {
		srv.mu.Lock()
		db = srv.byType[recordType]
		if db == nil {
			db = NewDB(recordType, srv.cfg.btreeDegree)
			srv.byType[recordType] = db
		}
		srv.mu.Unlock()
	}
	return db
}
