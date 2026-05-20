package envoy

import (
	"context"

	xrecording "github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/recording"
	"github.com/pomerium/pomerium/pkg/ipc"
)

func (srv *Server) disableSessionRecording(ctx context.Context) {
	recSrv := srv.recordingServer.Load()
	if recSrv != nil {
		log.Ctx(ctx).Info().Msg("disabling session recording server")
		if err := (*recSrv).Shutdown(ctx); err != nil {
			log.Ctx(ctx).Err(err).Msg("failed to shutdown sesssion recording server")
		}
		srv.recordingServer.Store(nil)
	}
}

func (srv *Server) shouldCreateRecordingServer() bool {
	if srv.recordingServer.Load() == nil {
		return true
	}
	select {
	case <-srv.recordingServerErrC:
		return true
	default:
	}
	return false
}

func (srv *Server) onConfigChangeRecordingServer(ctx context.Context, cfg *config.Config) {
	if recSrv := srv.recordingServer.Load(); recSrv != nil {
		(*recSrv).OnConfigChange(ctx, cfg)
	}
}

func (srv *Server) enableOrUpdateSessionRecording(
	ctx context.Context, cfg *config.Config, workers []*ipc.ProtoPipeWorker[*xrecording.RecordingData, *xrecording.RecordingCheckpoint],
) {
	if srv.shouldCreateRecordingServer() {
		log.Ctx(ctx).Info().Msg("initializing session recording server")
		newSrv, err := recording.NewRecordingServer(ctx, cfg, workers)
		if err != nil {
			panic(err)
		}
		go func() {
			srv.recordingServerErrC <- newSrv.Serve(ctx)
		}()
		srv.recordingServer.Store(&newSrv)
	} else {
		recSrv := srv.recordingServer.Load()
		if recSrv == nil {
			panic("bug: unreachable, the recording server should always be set in this code path")
		}
		log.Ctx(ctx).Info().Msg("updating session recording server")
		(*recSrv).OnConfigChange(ctx, cfg)
		(*recSrv).OnTransportChange(ctx, workers)
	}
}
