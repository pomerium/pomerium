package recording

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	gblob "gocloud.dev/blob"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/ipc"
	"github.com/pomerium/pomerium/pkg/storage/blob"
	"github.com/pomerium/pomerium/pkg/storage/blob/providers"
)

type Server interface {
	OnConfigChange(ctx context.Context, cfg *config.Config)
	OnTransportChange(
		ctx context.Context,
		workers []*ipc.ProtoPipeWorker[*recording.RecordingData, *recording.RecordingCheckpoint],
	)
	Serve(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

type recordingServer struct {
	cfgMu sync.RWMutex

	// bucket config
	blobCfg   atomic.Pointer[blob.StorageConfig]
	bucket    atomic.Pointer[gblob.Bucket]
	bucketErr error

	// server
	pipeServer        *ipc.ProtoPipeServer[*recording.RecordingData, *recording.RecordingCheckpoint]
	pipeServerHandler *Handler
	workerReload      chan []*ipc.ProtoPipeWorker[*recording.RecordingData, *recording.RecordingCheckpoint]
}

func NewRecordingServer(ctx context.Context, cfg *config.Config, workers []*ipc.ProtoPipeWorker[*recording.RecordingData, *recording.RecordingCheckpoint]) (Server, error) {
	if len(workers) == 0 {
		return nil, fmt.Errorf("no workers give to recording server")
	}

	r := &recordingServer{
		bucketErr:         fmt.Errorf("not initialized"),
		bucket:            atomic.Pointer[gblob.Bucket]{},
		workerReload:      make(chan []*ipc.ProtoPipeWorker[*recording.RecordingData, *recording.RecordingCheckpoint], 8),
		pipeServerHandler: newHandler(fmt.Sprintf("Pomerium/%s", version.FullVersion())),
	}
	r.pipeServer = ipc.NewProtoPipeServer(workers, r.pipeServerHandler, ipc.ServerOptions{
		ShutdownTimeout: time.Minute,
		Name:            "session-recording",
	})
	r.OnConfigChange(ctx, cfg)
	return r, nil
}

func (r *recordingServer) Serve(ctx context.Context) error {
	health.ReportRunning(health.RecordingHandler, health.StrAttr("transport", "pipe"))
	defer func() {
		health.ReportTerminating(health.RecordingHandler, health.StrAttr("transport", "pipe"))
	}()

	for {
		errC := make(chan error, 1)
		pipeServer := r.pipeServer

		go func() {
			errC <- pipeServer.Serve(ctx)
		}()
		select {
		case <-ctx.Done():
			if err := pipeServer.Shutdown(ctx); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to shutdown recording server")
			}
			return nil
		case err := <-errC:
			return err
		case workers := <-r.workerReload:
			workers = drainLatestReload(r.workerReload, workers)
			if err := pipeServer.Shutdown(ctx); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to shutdown recording server doing reload")
			}
			r.pipeServer = ipc.NewProtoPipeServer(workers, r.pipeServerHandler, ipc.ServerOptions{
				ShutdownTimeout: time.Minute,
				Name:            "session-recording",
			})
		}
	}
}

func (r *recordingServer) OnTransportChange(
	ctx context.Context,
	workers []*ipc.ProtoPipeWorker[*recording.RecordingData, *recording.RecordingCheckpoint],
) {
	if len(workers) == 0 {
		log.Ctx(ctx).Error().Msg("no workers passed to recording server")
		return
	}
	r.workerReload <- workers
}

func (r *recordingServer) Shutdown(ctx context.Context) error {
	r.cfgMu.Lock()
	defer r.cfgMu.Unlock()
	if err := r.pipeServer.Shutdown(ctx); err != nil {
		return fmt.Errorf("session recording: failed to shutdown: %w", err)
	}
	return nil
}

func (r *recordingServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	r.cfgMu.Lock()
	defer r.cfgMu.Unlock()
	if cfg.Options == nil || cfg.Options.BlobStorage == nil {
		log.Ctx(ctx).Info().Msg("recording server : blob storage configuration not yet set")
		return
	}
	r.handleBlobChange(ctx, cfg.Options.BlobStorage)
	r.blobCfg.Store(cfg.Options.BlobStorage)
	if r.bucketErr != nil {
		log.Ctx(ctx).Info().Err(r.bucketErr).
			Msg("skipping propagation of blob config to recording server transport due to errors")
		return
	}
	// propagate changes to server once the new bucket is opened and not before
	var prefix string
	if bc := r.blobCfg.Load(); bc != nil {
		prefix = bc.ManagedPrefix
	}
	r.pipeServerHandler.OnChange(ctx, r.bucket.Load(), prefix)
}

func (r *recordingServer) handleBlobChange(ctx context.Context, cfg *blob.StorageConfig) {
	curCfg := r.blobCfg.Load()

	var curBucketURI, newBucketURI string
	if curCfg != nil {
		curBucketURI = curCfg.BucketURI
	}
	if cfg != nil {
		newBucketURI = cfg.BucketURI
	}

	if curBucketURI == newBucketURI {
		// No changes needed.
		return
	}
	log.Ctx(ctx).Debug().Str("current-blob-uri", curBucketURI).Str("new-blob-uri", newBucketURI).Msg("updating recording server blob store")

	if curBucketURI != "" {
		log.Ctx(ctx).Debug().Str("blob-uri", curBucketURI).Msg("closing previous bucket")
		// Close the existing bucket.
		if bk := r.bucket.Load(); bk != nil {
			if err := bk.Close(); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to close pre-existing bucket")
			}
		}
	}

	if newBucketURI != "" {
		log.Ctx(ctx).Debug().Str("blob-uri", newBucketURI).Msg("opening new bucket")
		// Open the new bucket.
		bucket, err := providers.OpenBucket(ctx, newBucketURI)
		if err != nil {
			health.ReportError(health.BlobStorage, err)
			r.bucketErr = err
			r.bucket.Store(nil)
		} else {
			r.bucket.Store(bucket)
			r.bucketErr = nil
			health.ReportRunning(health.BlobStorage)
		}
	} else {
		// No new bucket.
		log.Ctx(ctx).Debug().Msg("setting empty bucket")
		r.bucket.Store(nil)
		r.bucketErr = fmt.Errorf("blob storage configuration is not set")
		health.ReportError(health.BlobStorage, r.bucketErr)
	}
}

func drainLatestReload[T any](ch chan T, latest T) T {
	for {
		select {
		case latest = <-ch:
		default:
			return latest
		}
	}
}
