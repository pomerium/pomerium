package databroker

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/session"
)

func newServer(cfg *serverConfig) *Server {
	return &Server{
		cfg: cfg,
		log: log.With().Str("service", "databroker").Logger(),
	}
}

func TestServer_Get(t *testing.T) {
	cfg := newServerConfig()
	t.Run("ignore deleted", func(t *testing.T) {
		srv := newServer(cfg)

		s := new(session.Session)
		s.Id = "1"
		any, err := anypb.New(s)
		assert.NoError(t, err)

		_, err = srv.Put(context.Background(), &databroker.PutRequest{
			Record: &databroker.Record{
				Type: any.TypeUrl,
				Id:   s.Id,
				Data: any,
			},
		})
		assert.NoError(t, err)
		_, err = srv.Put(context.Background(), &databroker.PutRequest{
			Record: &databroker.Record{
				Type:      any.TypeUrl,
				Id:        s.Id,
				DeletedAt: timestamppb.Now(),
			},
		})
		assert.NoError(t, err)
		_, err = srv.Get(context.Background(), &databroker.GetRequest{
			Type: any.TypeUrl,
			Id:   s.Id,
		})
		assert.Error(t, err)
		assert.Equal(t, codes.NotFound, status.Code(err))
	})
}
