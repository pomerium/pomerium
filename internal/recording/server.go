package recording

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	gblob "gocloud.dev/blob"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/version"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/storage/blob"
	"github.com/pomerium/pomerium/pkg/storage/blob/middleware"
	"github.com/pomerium/pomerium/pkg/storage/blob/providers"
)

type Server interface {
	OnConfigChange(ctx context.Context, cfg *config.Config)
	recording.RecordingServiceServer
}

type recordingServer struct {
	recording.UnsafeRecordingServiceServer

	sem *semaphore.Weighted

	cfgMu sync.RWMutex

	blobCfg   atomic.Pointer[blob.StorageConfig]
	bucket    atomic.Pointer[gblob.Bucket]
	bucketErr error

	identity string

	// TODO : needs to be handled
	mode    string
	pipeIPC *pipeIPC
}

func NewRecordingServer(ctx context.Context, cfg *config.Config) Server {
	r := &recordingServer{
		bucketErr: fmt.Errorf("not initialized"),
		bucket:    atomic.Pointer[gblob.Bucket]{},
		sem:       semaphore.NewWeighted(10000),
		identity:  fmt.Sprintf("Pomerium/%s", version.FullVersion()),
	}
	r.OnConfigChange(ctx, cfg)
	return r
}

type grpcTransport struct {
	stream grpc.BidiStreamingServer[recording.RecordingData, recording.RecordingCheckpoint]
}

func (g grpcTransport) Recv(_ context.Context) (*recording.RecordingData, error) {
	return g.stream.Recv()
}

func (g grpcTransport) Send(_ context.Context, s *recording.RecordingCheckpoint) error {
	return g.stream.Send(s)
}

func (r *recordingServer) Record(stream grpc.BidiStreamingServer[recording.RecordingData, recording.RecordingCheckpoint]) error {
	if r.mode != "grpc" {
		return status.Error(codes.FailedPrecondition, "session recording IPC mode is not gRPC")
	}
	ctx := middleware.ContextWithBlobUserAgent(stream.Context(), r.identity)
	if !r.sem.TryAcquire(1) {
		return status.Error(codes.ResourceExhausted, "max concurrency exceeded")
	}
	defer r.sem.Release(1)

	bucket, prefix, bucketErr := r.loadStreamConfig()
	if bucketErr != nil {
		return status.Error(codes.Unavailable, fmt.Sprintf("failed to load bucket from configuration: %s", bucketErr))
	}

	err := RunProtocol(ctx, grpcTransport{stream: stream}, bucket, prefix)
	if err != nil {
		log.Ctx(ctx).Err(err).Msg("recording protocol terminated")
	}
	return statusFromProtocolErr(err)
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
	}
}

func (r *recordingServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	r.cfgMu.Lock()
	defer r.cfgMu.Unlock()
	r.handleBlobChange(ctx, cfg.Options.BlobStorage)
	// propagate changes to server once the new bucket is opened and not before
	r.blobCfg.Store(cfg.Options.BlobStorage)

	// TODO :
	r.onConfigChangeMode(ctx, cfg)
}

func (r *recordingServer) onConfigChangeMode(ctx context.Context, cfg *config.Config) {
	curMode := r.mode
	incomingMode := cfg.Options.SessionRecordingIpcMode
	if incomingMode == nil {
		panic("handle nil incoming mode")
	}
	log.Ctx(ctx).Debug().
		Str("cur-ipc-mode", curMode).
		Str("incoming-ipc-mode", *incomingMode).Msg("configuring server")

	if curMode != *incomingMode {
		switch curMode {
		case "pipe":
			if err := r.pipeIPC.Close(); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to close current pipes for IPC in session recording")
			}
		case "grpc":
			// disconnect clients
		default:
			panic("handle unknown type")
		}

		switch *incomingMode {
		case "pipe":
			// setup recording pipes

			// broadcast change to envoy
		}
	} else {
		log.Ctx(ctx).Debug().Msg("recording server: nothing to change for ipc communication")
	}
	curMode = *incomingMode
}

func (r *recordingServer) loadStreamConfig() (bucket *gblob.Bucket, prefix string, err error) {
	r.cfgMu.RLock()
	defer r.cfgMu.RUnlock()
	return r.bucket.Load(), r.blobCfg.Load().ManagedPrefix, r.bucketErr
}

var _ recording.RecordingServiceServer = (*recordingServer)(nil)
