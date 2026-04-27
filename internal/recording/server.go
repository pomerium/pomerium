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

const (
	modeGRPC = "grpc"
	modePipe = "pipe"
)

type Options struct {
	Pipes []*Pipes
}

type Option func(*Options)

// WithPipes supplies pre-opened IPC pipes to be used by the server side
// of the SSH session recording transport
func WithPipes(pipes []*Pipes) Option {
	return func(o *Options) {
		o.Pipes = pipes
	}
}

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
	// transportMode is set once at initialization
	transportMode string

	grpcBucketChange chan bucketConfigUpdate
	pipeIPC          *PipeIPC
}

type bucketConfigUpdate struct {
	bucket        *gblob.Bucket
	managedPrefix string
}

func NewRecordingServer(ctx context.Context, cfg *config.Config, opts ...Option) Server {
	options := &Options{}
	for _, opt := range opts {
		opt(options)
	}
	var conc int32
	if cfg.Options.SessionRecordingConcurrency != nil {
		conc = *cfg.Options.SessionRecordingConcurrency
	} else {
		conc = 8
	}
	var mode string
	if cfg.Options.SessionRecordingIpcMode != nil {
		mode = *cfg.Options.SessionRecordingIpcMode
	} else {
		mode = "pipe"
	}
	r := &recordingServer{
		bucketErr:        fmt.Errorf("not initialized"),
		bucket:           atomic.Pointer[gblob.Bucket]{},
		sem:              semaphore.NewWeighted(10000),
		identity:         fmt.Sprintf("Pomerium/%s", version.FullVersion()),
		grpcBucketChange: make(chan bucketConfigUpdate, conc),
		transportMode:    mode,
	}
	if r.transportMode == modePipe {
		r.pipeIPC = NewPipeIPC(r.identity, r.bucket.Load(), "", options.Pipes)
	}
	r.OnConfigChange(ctx, cfg)
	return r
}

type grpcTransport struct {
	stream grpc.BidiStreamingServer[recording.RecordingData, recording.RecordingCheckpoint]

	cfgMu  sync.Mutex
	bucket *gblob.Bucket
	prefix string
}

func (g *grpcTransport) Recv(_ context.Context) (*recording.RecordingData, error) {
	return g.stream.Recv()
}

func (g *grpcTransport) Send(_ context.Context, s *recording.RecordingCheckpoint) error {
	return g.stream.Send(s)
}

func (g *grpcTransport) OnChange(bucket *gblob.Bucket, managedPrefix string) {
	g.cfgMu.Lock()
	defer g.cfgMu.Unlock()
	g.bucket, g.prefix = bucket, managedPrefix
}

func (g *grpcTransport) currentConfig() (bucket *gblob.Bucket, managedPrefix string) {
	g.cfgMu.Lock()
	defer g.cfgMu.Unlock()
	return g.bucket, g.prefix
}

var _ TransportProtocol = (*grpcTransport)(nil)

func (r *recordingServer) Record(stream grpc.BidiStreamingServer[recording.RecordingData, recording.RecordingCheckpoint]) error {
	if r.transportMode != "grpc" {
		return status.Error(codes.FailedPrecondition, "session recording IPC mode is not gRPC")
	}
	ctx := middleware.ContextWithBlobUserAgent(stream.Context(), r.identity)
	if !r.sem.TryAcquire(1) {
		return status.Error(codes.ResourceExhausted, "max concurrency exceeded")
	}
	defer r.sem.Release(1)

	bucket, prefix, bucketErr := r.loadCurStreamConfig()
	if bucketErr != nil {
		return status.Error(codes.Unavailable, fmt.Sprintf("failed to load bucket from configuration: %s", bucketErr))
	}

	done := make(chan struct{})
	tr := &grpcTransport{stream: stream}
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case upd := <-r.grpcBucketChange:
				tr.OnChange(upd.bucket, upd.managedPrefix)
			}
		}
	}()
	return RunProtocol(ctx, tr, bucket, prefix)
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
	var prefix string
	if bc := r.blobCfg.Load(); bc != nil {
		prefix = bc.ManagedPrefix
	}
	switch r.transportMode {
	case modeGRPC:
		r.grpcBucketChange <- bucketConfigUpdate{bucket: r.bucket.Load(), managedPrefix: prefix}
	case modePipe:
		log.Ctx(ctx).Debug().Msg("propagating bucket changes to pipes")
		r.pipeIPC.OnChange(r.bucket.Load(), prefix)
	}
}

func (r *recordingServer) loadCurStreamConfig() (bucket *gblob.Bucket, prefix string, err error) {
	r.cfgMu.RLock()
	defer r.cfgMu.RUnlock()
	return r.bucket.Load(), r.blobCfg.Load().ManagedPrefix, r.bucketErr
}

var _ recording.RecordingServiceServer = (*recordingServer)(nil)
