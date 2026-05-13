package recording

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	gblob "gocloud.dev/blob"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/storage/blob"
	"github.com/pomerium/pomerium/pkg/storage/blob/providers"
)

type TransportOptions struct {
	Pipes       []*Pipes
	Concurrency uint32
}

func (o *TransportOptions) Validate() error {
	if len(o.Pipes) == 0 {
		return fmt.Errorf("recording server : pipes configured, but none available")
	}
	return nil
}

type Server interface {
	OnConfigChange(ctx context.Context, cfg *config.Config)
	OnTransportChange(ctx context.Context, trOptions TransportOptions)
	Serve(ctx context.Context) error
	Shutdown(ctx context.Context) error
}

type recordingServer struct {
	cfgMu sync.RWMutex

	blobCfg   atomic.Pointer[blob.StorageConfig]
	bucket    atomic.Pointer[gblob.Bucket]
	bucketErr error

	identity string

	cfgChange           chan bucketConfigUpdate
	grpcTransportChange []chan bucketConfigUpdate
	pipeIPC             *PipeIPC
	transportOptions    TransportOptions

	pipeReloadChange chan pipeConfigChange
}

type pipeConfigChange struct {
	identity string
	pipes    []*Pipes
}

type bucketConfigUpdate struct {
	bucket        *gblob.Bucket
	managedPrefix string
}

func NewRecordingServer(ctx context.Context, cfg *config.Config, trOpts TransportOptions) (Server, error) {
	if err := trOpts.Validate(); err != nil {
		return nil, err
	}

	r := &recordingServer{
		bucketErr:           fmt.Errorf("not initialized"),
		bucket:              atomic.Pointer[gblob.Bucket]{},
		identity:            fmt.Sprintf("Pomerium/%s", version.FullVersion()),
		cfgChange:           make(chan bucketConfigUpdate, 16),
		grpcTransportChange: []chan bucketConfigUpdate{},
		pipeReloadChange:    make(chan pipeConfigChange, 16),
		transportOptions:    trOpts,
	}
	r.pipeIPC = NewPipeIPC(r.identity, r.bucket.Load(), "", trOpts.Pipes)
	r.OnConfigChange(ctx, cfg)
	return r, nil
}

func (r *recordingServer) Serve(ctx context.Context) error {
	health.ReportRunning(health.RecordingHandler, health.StrAttr("transport", "pipe"))
	defer func() {
		health.ReportTerminating(health.RecordingHandler, health.StrAttr("transport", "pipe"))
	}()

	for {
		r.cfgMu.RLock()
		cur := r.pipeIPC
		r.cfgMu.RUnlock()
		if cur == nil {
			return fmt.Errorf("recording server: pipe IPC not initialized")
		}

		serveErr := make(chan error, 1)
		go func() { serveErr <- cur.Serve(ctx) }()

		select {
		case <-ctx.Done():
			_ = cur.Shutdown(context.WithoutCancel(ctx))
			<-serveErr
			return ctx.Err()
		case err := <-serveErr:
			return err
		case upd := <-r.pipeReloadChange:
			upd = drainLatestReload(r.pipeReloadChange, upd)
			log.Ctx(ctx).Info().Msg("reloading session recording pipe transport")
			if err := cur.Shutdown(ctx); err != nil {
				log.Ctx(ctx).Warn().Err(err).Msg("failed to gracefully shutdown previous pipe transport during reload")
			}
			<-serveErr

			r.cfgMu.Lock()
			r.pipeIPC = NewPipeIPC(upd.identity, r.bucket.Load(), r.blobCfg.Load().ManagedPrefix, upd.pipes)
			r.cfgMu.Unlock()
		}
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

func (r *recordingServer) Shutdown(ctx context.Context) error {
	r.cfgMu.Lock()
	defer r.cfgMu.Unlock()
	if err := r.pipeIPC.Shutdown(ctx); err != nil {
		return fmt.Errorf("session recording: failed to shutdown: %w", err)
	}
	return nil
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

func (r *recordingServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	r.cfgMu.Lock()
	defer r.cfgMu.Unlock()
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
	r.pipeIPC.OnChange(r.bucket.Load(), prefix)
}

func (r *recordingServer) OnTransportChange(ctx context.Context, trOpts TransportOptions) {
	r.propagatePipeTransportChange(ctx, trOpts)
}

func (r *recordingServer) arePipesDifferent(newPipes []*Pipes) (shouldSwap bool) {
	r.cfgMu.Lock()
	originalPipes := r.pipeIPC.pipes
	r.cfgMu.Unlock()
	if len(originalPipes) != len(newPipes) {
		return true
	}
	for i := range originalPipes {
		if originalPipes[i] != newPipes[i] {
			return true
		}
	}
	return false
}

func (r *recordingServer) propagatePipeTransportChange(ctx context.Context, trOpts TransportOptions) {
	if err := trOpts.Validate(); err != nil {
		log.Ctx(ctx).Err(err).Msg("invalid configuration passed on update to session recording pipe transport, skipping")
		return
	}
	if len(trOpts.Pipes) > 0 && r.arePipesDifferent(trOpts.Pipes) {
		select {
		case r.pipeReloadChange <- pipeConfigChange{
			identity: r.identity,
			pipes:    trOpts.Pipes,
		}:
		default:
			log.Ctx(ctx).Warn().Msg("failed to update session recording pipe transport with new configuration")
		}
	} else {
		log.Ctx(ctx).Debug().Msg("propagating bucket changes to pipes")
	}
}
