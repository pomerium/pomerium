package databroker

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/signal"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/storage"
)

func newServer(cfg *serverConfig) *Server {
	return &Server{
		version: uuid.New().String(),
		cfg:     cfg,
		log:     log.With().Str("service", "databroker").Logger(),

		byType:       make(map[string]storage.Backend),
		onTypechange: signal.New(),
	}
}

func TestServer_initVersion(t *testing.T) {
	cfg := newServerConfig()
	t.Run("nil db", func(t *testing.T) {
		srvVersion := uuid.New()
		oldNewUUID := newUUID
		newUUID = func() uuid.UUID {
			return srvVersion
		}
		defer func() { newUUID = oldNewUUID }()

		srv := newServer(cfg)
		srv.byType[recordTypeServerVersion] = nil
		srv.initVersion()
		assert.Equal(t, srvVersion.String(), srv.version)
	})
	t.Run("new server with random version", func(t *testing.T) {
		srvVersion := uuid.New()
		oldNewUUID := newUUID
		newUUID = func() uuid.UUID {
			return srvVersion
		}
		defer func() { newUUID = oldNewUUID }()

		srv := newServer(cfg)
		ctx := context.Background()
		db, _, err := srv.getBackend(recordTypeServerVersion, false)
		require.NoError(t, err)
		r, err := db.Get(ctx, serverVersionKey)
		assert.Error(t, err)
		assert.Nil(t, r)
		srv.initVersion()
		assert.Equal(t, srvVersion.String(), srv.version)
		r, err = db.Get(ctx, serverVersionKey)
		require.NoError(t, err)
		assert.NotNil(t, r)
		var sv databroker.ServerVersion
		assert.NoError(t, ptypes.UnmarshalAny(r.GetData(), &sv))
		assert.Equal(t, srvVersion.String(), sv.Version)
	})
	t.Run("init version twice should get the same version", func(t *testing.T) {
		srv := newServer(cfg)
		ctx := context.Background()
		db, _, err := srv.getBackend(recordTypeServerVersion, false)
		require.NoError(t, err)
		r, err := db.Get(ctx, serverVersionKey)
		assert.Error(t, err)
		assert.Nil(t, r)

		srv.initVersion()
		srvVersion := srv.version

		r, err = db.Get(ctx, serverVersionKey)
		require.NoError(t, err)
		assert.NotNil(t, r)
		var sv databroker.ServerVersion
		assert.NoError(t, ptypes.UnmarshalAny(r.GetData(), &sv))
		assert.Equal(t, srvVersion, sv.Version)

		// re-init version should get the same value as above
		srv.version = "foo"
		srv.initVersion()
		assert.Equal(t, srvVersion, srv.version)
	})
}

func TestServer_Get(t *testing.T) {
	cfg := newServerConfig()
	t.Run("ignore deleted", func(t *testing.T) {
		srv := newServer(cfg)

		s := new(session.Session)
		s.Id = "1"
		any, err := anypb.New(s)
		assert.NoError(t, err)

		srv.Set(context.Background(), &databroker.SetRequest{
			Type: any.TypeUrl,
			Id:   s.Id,
			Data: any,
		})
		srv.Delete(context.Background(), &databroker.DeleteRequest{
			Type: any.TypeUrl,
			Id:   s.Id,
		})
		_, err = srv.Get(context.Background(), &databroker.GetRequest{
			Type: any.TypeUrl,
			Id:   s.Id,
		})
		assert.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}

func TestServer_GetAll(t *testing.T) {
	cfg := newServerConfig(
		WithGetAllPageSize(5),
	)
	t.Run("ignore deleted", func(t *testing.T) {
		srv := newServer(cfg)

		s := new(session.Session)
		s.Id = "1"
		any, err := anypb.New(s)
		assert.NoError(t, err)

		srv.Set(context.Background(), &databroker.SetRequest{
			Type: any.TypeUrl,
			Id:   s.Id,
			Data: any,
		})
		srv.Delete(context.Background(), &databroker.DeleteRequest{
			Type: any.TypeUrl,
			Id:   s.Id,
		})
		res, err := srv.GetAll(context.Background(), &databroker.GetAllRequest{
			Type: any.TypeUrl,
		})
		assert.NoError(t, err)
		assert.Len(t, res.GetRecords(), 0)
	})
	t.Run("paging", func(t *testing.T) {
		srv := newServer(cfg)

		any, err := anypb.New(wrapperspb.String("TEST"))
		assert.NoError(t, err)

		for i := 0; i < 7; i++ {
			srv.Set(context.Background(), &databroker.SetRequest{
				Type: any.TypeUrl,
				Id:   fmt.Sprint(i),
				Data: any,
			})
		}

		res, err := srv.GetAll(context.Background(), &databroker.GetAllRequest{
			Type: any.TypeUrl,
		})
		assert.NoError(t, err)
		assert.Len(t, res.GetRecords(), 5)
		assert.Equal(t, res.GetNextPageToken(), "000000000005")

		res, err = srv.GetAll(context.Background(), &databroker.GetAllRequest{
			Type:      any.TypeUrl,
			PageToken: res.GetNextPageToken(),
		})
		assert.NoError(t, err)
		assert.Len(t, res.GetRecords(), 2)
		assert.Equal(t, res.GetNextPageToken(), "")
	})
}
