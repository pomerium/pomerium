package databroker

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/storage"
)

func newServer(cfg *serverConfig) *Server {
	return &Server{
		version: uuid.New().String(),
		cfg:     cfg,
		log:     log.With().Str("service", "databroker").Logger(),

		byType:   make(map[string]storage.Backend),
		onchange: NewSignal(),
	}
}

func TestServer_initVersion(t *testing.T) {
	cfg := newServerConfig()
	t.Run("nil db", func(t *testing.T) {
		srv := newServer(cfg)
		srvVersion := uuid.New().String()
		srv.version = srvVersion
		srv.byType[recordTypeServerVersion] = nil
		srv.initVersion()
		assert.Equal(t, srvVersion, srv.version)
	})
	t.Run("new server with random version", func(t *testing.T) {
		srv := newServer(cfg)
		ctx := context.Background()
		db := srv.getDB(recordTypeServerVersion)
		r := db.Get(ctx, serverVersionKey)
		assert.Nil(t, r)
		srvVersion := uuid.New().String()
		srv.version = srvVersion
		srv.initVersion()
		assert.Equal(t, srvVersion, srv.version)
		r = db.Get(ctx, serverVersionKey)
		assert.NotNil(t, r)
		assert.Equal(t, srv.version, string(r.Data.Value))
	})
	t.Run("init version twice should get the same version", func(t *testing.T) {
		srv := newServer(cfg)
		ctx := context.Background()
		db := srv.getDB(recordTypeServerVersion)
		r := db.Get(ctx, serverVersionKey)
		assert.Nil(t, r)
		srvVersion := uuid.New().String()
		srv.version = srvVersion
		srv.initVersion()
		assert.Equal(t, srvVersion, srv.version)
		r = db.Get(ctx, serverVersionKey)
		assert.NotNil(t, r)
		assert.Equal(t, srv.version, string(r.Data.Value))

		// re-init version should get the same value as above
		srv.initVersion()
		assert.Equal(t, srvVersion, srv.version)
	})
}
