package recording

import (
	"context"
	"slices"
	"sync/atomic"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/recording"
	"github.com/pomerium/pomerium/pkg/grpcutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type securedRecordingServer struct {
	sharedKey  atomic.Pointer[[]byte]
	underlying Server
}

func (srv *securedRecordingServer) authorize(ctx context.Context) error {
	sharedKey := srv.sharedKey.Load()
	if sharedKey == nil {
		return status.Error(codes.Unavailable, "no shared key defined")
	}
	return grpcutil.RequireSignedJWT(ctx, *sharedKey)
}

func (s *securedRecordingServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	sharedKey, err := cfg.Options.GetSharedKey()
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("databroker: failed to load shared key")
		return
	}
	sharedKey = slices.Clone(sharedKey)
	s.sharedKey.Store(&sharedKey)
}

func (s *securedRecordingServer) Record(stream grpc.ClientStreamingServer[recording.RecordingData, emptypb.Empty]) error {
	if err := s.authorize(stream.Context()); err != nil {
		return err
	}
	return s.underlying.Record(stream)
}
