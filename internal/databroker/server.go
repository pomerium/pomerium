// Package databroker contains a data broker implementation.
package databroker

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/go-cmp/cmp"
	"github.com/rs/zerolog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/trace"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/inmemory"
	"github.com/pomerium/pomerium/pkg/storage/redis"
)

// Server implements the databroker service using an in memory database.
type Server struct {
	cfg *serverConfig
	log zerolog.Logger

	mu      sync.RWMutex
	backend storage.Backend
}

// New creates a new server.
func New(options ...ServerOption) *Server {
	srv := &Server{
		log: log.With().Str("service", "databroker").Logger(),
	}
	srv.UpdateConfig(options...)
	return srv
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
}

// Get gets a record from the in-memory list.
func (srv *Server) Get(ctx context.Context, req *databroker.GetRequest) (*databroker.GetResponse, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.Get")
	defer span.End()
	srv.log.Info().
		Str("peer", grpcutil.GetPeerAddr(ctx)).
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

// Query queries for records.
func (srv *Server) Query(ctx context.Context, req *databroker.QueryRequest) (*databroker.QueryResponse, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.Query")
	defer span.End()
	srv.log.Info().
		Str("peer", grpcutil.GetPeerAddr(ctx)).
		Str("type", req.GetType()).
		Str("query", req.GetQuery()).
		Int64("offset", req.GetOffset()).
		Int64("limit", req.GetLimit()).
		Msg("query")

	query := strings.ToLower(req.GetQuery())

	db, err := srv.getBackend()
	if err != nil {
		return nil, err
	}

	all, _, err := db.GetAll(ctx)
	if err != nil {
		return nil, err
	}

	var filtered []*databroker.Record
	for _, record := range all {
		if record.GetType() != req.GetType() {
			continue
		}
		if query != "" && !storage.MatchAny(record.GetData(), query) {
			continue
		}
		filtered = append(filtered, record)
	}

	records, totalCount := databroker.ApplyOffsetAndLimit(filtered, int(req.GetOffset()), int(req.GetLimit()))
	return &databroker.QueryResponse{
		Records:    records,
		TotalCount: int64(totalCount),
	}, nil
}

// Put updates an existing record or adds a new one.
func (srv *Server) Put(ctx context.Context, req *databroker.PutRequest) (*databroker.PutResponse, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.Put")
	defer span.End()
	record := req.GetRecord()

	srv.log.Info().
		Str("peer", grpcutil.GetPeerAddr(ctx)).
		Str("type", record.GetType()).
		Str("id", record.GetId()).
		Msg("put")

	db, err := srv.getBackend()
	if err != nil {
		return nil, err
	}

	serverVersion, err := db.Put(ctx, record)
	if err != nil {
		return nil, err
	}
	return &databroker.PutResponse{
		ServerVersion: serverVersion,
		Record:        record,
	}, nil
}

// SetOptions sets options for a type in the databroker.
func (srv *Server) SetOptions(ctx context.Context, req *databroker.SetOptionsRequest) (*databroker.SetOptionsResponse, error) {
	_, span := trace.StartSpan(ctx, "databroker.grpc.SetOptions")
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

	srv.log.Info().
		Str("peer", grpcutil.GetPeerAddr(stream.Context())).
		Uint64("server_version", req.GetServerVersion()).
		Uint64("record_version", req.GetRecordVersion()).
		Msg("sync")

	backend, err := srv.getBackend()
	if err != nil {
		return err
	}

	recordStream, err := backend.Sync(ctx, req.GetServerVersion(), req.GetRecordVersion())
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

	srv.log.Info().
		Str("peer", grpcutil.GetPeerAddr(stream.Context())).
		Str("type", req.GetType()).
		Msg("sync latest")

	backend, err := srv.getBackend()
	if err != nil {
		return err
	}

	records, versions, err := backend.GetAll(ctx)
	if err != nil {
		return err
	}

	for _, record := range records {
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

	// always send the server version last in case there are no records
	return stream.Send(&databroker.SyncLatestResponse{
		Response: &databroker.SyncLatestResponse_Versions{
			Versions: versions,
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
		srv.log.Info().Msg("using in-memory store")
		return inmemory.New(), nil
	case config.StorageRedisName:
		srv.log.Info().Msg("using redis store")
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
