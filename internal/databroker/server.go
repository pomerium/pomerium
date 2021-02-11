// Package databroker contains a data broker implementation.
package databroker

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/cryptutil"
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
	cfg *serverConfig
	log zerolog.Logger

	mu           sync.RWMutex
	version      uint64
	backend      storage.Backend
	onTypechange *signal.Signal
}

// New creates a new server.
func New(options ...ServerOption) *Server {
	srv := &Server{
		log:          log.With().Str("service", "databroker").Logger(),
		onTypechange: signal.New(),
	}
	srv.UpdateConfig(options...)
	return srv
}

func (srv *Server) initVersion() {
	dbServerVersion, _, err := srv.getBackend(false)
	if err != nil {
		log.Error().Err(err).Msg("failed to init server version")
		return
	}

	// Get version from storage first.
	if r, _ := dbServerVersion.Get(context.Background(), recordTypeServerVersion, serverVersionKey); r != nil {
		var sv wrapperspb.UInt64Value
		if err := ptypes.UnmarshalAny(r.GetData(), &sv); err == nil {
			srv.log.Debug().Uint64("server_version", sv.Value).Msg("got db version from Backend")
			srv.version = sv.Value
		}
		return
	}

	srv.version = cryptutil.NewRandomUInt64()
	data, _ := anypb.New(wrapperspb.UInt64(srv.version))
	if err := dbServerVersion.Put(context.Background(), &databroker.Record{
		Type: recordTypeServerVersion,
		Id:   serverVersionKey,
		Data: data,
	}); err != nil {
		srv.log.Warn().Err(err).Msg("failed to save server version.")
	}
}

// UpdateConfig updates the server with the new options.
func (srv *Server) UpdateConfig(options ...ServerOption) {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	cfg := newServerConfig(options...)
	if cmp.Equal(cfg, srv.cfg, cmp.AllowUnexported(serverConfig{})) {
		log.Debug().Msg("databroker: no changes detected, re-using existing DBs")
		return
	}
	srv.cfg = cfg

	if srv.backend != nil {
		err := srv.backend.Close()
		if err != nil {
			log.Error().Err(err).Msg("databroker: error closing backend")
		}
		srv.backend = nil
	}

	srv.initVersion()
}

// Get gets a record from the in-memory list.
func (srv *Server) Get(ctx context.Context, req *databroker.GetRequest) (*databroker.GetResponse, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.Get")
	defer span.End()
	srv.log.Info().
		Str("type", req.GetType()).
		Str("id", req.GetId()).
		Msg("get")

	db, _, err := srv.getBackend(true)
	if err != nil {
		return nil, err
	}
	record, err := db.Get(ctx, req.GetType(), req.GetId())
	if err != nil {
		return nil, status.Error(codes.NotFound, "record not found")
	}
	if record.DeletedAt != nil {
		return nil, status.Error(codes.NotFound, "record not found")
	}
	return &databroker.GetResponse{Record: record}, nil
}

// Query queries for records.
func (srv *Server) Query(ctx context.Context, req *databroker.QueryRequest) (*databroker.QueryResponse, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.Query")
	defer span.End()
	srv.log.Info().
		Str("type", req.GetType()).
		Str("query", req.GetQuery()).
		Int64("offset", req.GetOffset()).
		Int64("limit", req.GetLimit()).
		Msg("query")

	query := strings.ToLower(req.GetQuery())

	db, _, err := srv.getBackend(true)
	if err != nil {
		return nil, err
	}

	all, err := db.GetAll(ctx)
	if err != nil {
		return nil, err
	}

	var filtered []*databroker.Record
	for _, record := range all {
		if record.DeletedAt == nil && storage.MatchAny(record.GetData(), query) {
			filtered = append(filtered, record)
		}
	}

	records, totalCount := databroker.ApplyOffsetAndLimit(filtered, int(req.GetOffset()), int(req.GetLimit()))
	return &databroker.QueryResponse{
		Records:    records,
		TotalCount: int64(totalCount),
	}, nil
}

// Put updates a record in the in-memory list, or adds a new one.
func (srv *Server) Put(ctx context.Context, req *databroker.PutRequest) (*databroker.PutResponse, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.Put")
	defer span.End()
	record := req.GetRecord()

	srv.log.Info().
		Str("type", record.GetType()).
		Str("id", record.GetId()).
		Msg("put")

	db, version, err := srv.getBackend(true)
	if err != nil {
		return nil, err
	}
	if err := db.Put(ctx, record); err != nil {
		return nil, err
	}
	return &databroker.PutResponse{
		ServerVersion: version,
		Record:        record,
	}, nil
}

// Sync streams updates for the given record type.
func (srv *Server) Sync(req *databroker.SyncRequest, stream databroker.DataBrokerService_SyncServer) error {
	_, span := trace.StartSpan(stream.Context(), "databroker.grpc.Sync")
	defer span.End()
	srv.log.Info().
		Uint64("server_version", req.GetServerVersion()).
		Uint64("record_version", req.GetRecordVersion()).
		Msg("sync")

	backend, serverVersion, err := srv.getBackend(true)
	if err != nil {
		return err
	}

	// reset record version if the server versions don't match
	if req.GetServerVersion() != serverVersion {
		return status.Errorf(codes.Aborted, "invalid server version, expected: %d", req.GetServerVersion())
	}

	ctx := stream.Context()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	recordStream, err := backend.Sync(ctx, req.GetRecordVersion())
	if err != nil {
		return err
	}
	defer func() { _ = recordStream.Close() }()

	for recordStream.Next(true) {
		err = stream.Send(&databroker.SyncResponse{
			ServerVersion: serverVersion,
			Record:        recordStream.Record(),
		})
		if err != nil {
			return err
		}
	}

	return recordStream.Err()
}

// SyncLatest returns the latest value of every record in the databroker as a stream of records.
func (srv *Server) SyncLatest(_ *emptypb.Empty, stream databroker.DataBrokerService_SyncLatestServer) error {
	_, span := trace.StartSpan(stream.Context(), "databroker.grpc.SyncLatest")
	defer span.End()
	srv.log.Info().
		Msg("sync latest")

	backend, serverVersion, err := srv.getBackend(true)
	if err != nil {
		return err
	}

	ctx := stream.Context()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	records, err := backend.GetAll(ctx)
	if err != nil {
		return err
	}

	for _, record := range records {
		err = stream.Send(&databroker.SyncResponse{
			ServerVersion: serverVersion,
			Record:        record,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func (srv *Server) getBackend(lock bool) (backend storage.Backend, version uint64, err error) {
	// double-checked locking:
	// first try the read lock, then re-try with the write lock, and finally create a new backend if nil
	if lock {
		srv.mu.RLock()
	}
	backend = srv.backend
	version = srv.version
	if lock {
		srv.mu.RUnlock()
	}
	if backend == nil {
		if lock {
			srv.mu.Lock()
		}
		backend = srv.backend
		version = srv.version
		var err error
		if backend == nil {
			backend, err = srv.newBackend()
			srv.backend = backend
			defer srv.onTypechange.Broadcast()
		}
		if lock {
			srv.mu.Unlock()
		}
		if err != nil {
			return nil, 0, err
		}
	}
	return backend, version, nil
}

func (srv *Server) newBackend() (backend storage.Backend, err error) {
	caCertPool, err := cryptutil.GetCertPool("", srv.cfg.storageCAFile)
	if err != nil {
		log.Warn().Err(err).Msg("failed to read databroker CA file")
	}
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
		// nolint: gosec
		InsecureSkipVerify: srv.cfg.storageCertSkipVerify,
	}
	if srv.cfg.storageCertificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*srv.cfg.storageCertificate}
	}

	switch srv.cfg.storageType {
	case config.StorageInMemoryName:
		return inmemory.New(), nil
	case config.StorageRedisName:
		backend, err = redis.New(
			srv.cfg.storageConnectionString,
			redis.WithTLSConfig(tlsConfig),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create new redis storage: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported storage type: %s", srv.cfg.storageType)
	}
	if srv.cfg.secret != nil {
		backend, err = storage.NewEncryptedBackend(srv.cfg.secret, backend)
		if err != nil {
			return nil, err
		}
	}
	return backend, nil
}
