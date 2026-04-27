package recording

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	gblob "gocloud.dev/blob"
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
	ModeGRPC = "grpc"
	ModePipe = "pipe"
)

type Options struct {
	TransportMode string
	Pipes         []*Pipes
	Concurrency   uint32
}

func (o *Options) Validate() error {
	if o.TransportMode == "pipe" && len(o.Pipes) == 0 {
		return fmt.Errorf("recording server : pipes configured, but none available")
	}
	return nil
}

type Option func(*Options)

// WithPipes supplies pre-opened IPC pipes to be used by the server side
// of the SSH session recording transport
func WithPipes(pipes []*Pipes) Option {
	return func(o *Options) {
		o.Pipes = pipes
	}
}

func WithTransportMode(trMode string) Option {
	return func(o *Options) {
		o.TransportMode = trMode
	}
}

func WithConcurrecy(conc uint32) Option {
	return func(o *Options) {
		o.Concurrency = conc
	}
}

func defaultOptions() *Options {
	return &Options{
		TransportMode: ModePipe,
		Pipes:         []*Pipes{},
		Concurrency:   8,
	}
}

type Server interface {
	OnConfigChange(ctx context.Context, cfg *config.Config)
	Serve(ctx context.Context) error
	Shutdown(ctx context.Context) error
	recording.RecordingServiceServer
}

type recordingServer struct {
	recording.UnsafeRecordingServiceServer

	cfgMu sync.RWMutex

	blobCfg   atomic.Pointer[blob.StorageConfig]
	bucket    atomic.Pointer[gblob.Bucket]
	bucketErr error

	identity string

	cfgChange           chan bucketConfigUpdate
	grpcTransportChange []chan bucketConfigUpdate
	pipeIPC             *PipeIPC
	*Options
}

type bucketConfigUpdate struct {
	bucket        *gblob.Bucket
	managedPrefix string
}

func NewRecordingServer(ctx context.Context, cfg *config.Config, opts ...Option) (Server, error) {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}
	if err := options.Validate(); err != nil {
		return nil, err
	}

	r := &recordingServer{
		bucketErr:           fmt.Errorf("not initialized"),
		bucket:              atomic.Pointer[gblob.Bucket]{},
		identity:            fmt.Sprintf("Pomerium/%s", version.FullVersion()),
		cfgChange:           make(chan bucketConfigUpdate, options.Concurrency),
		grpcTransportChange: []chan bucketConfigUpdate{},
		Options:             options,
	}
	if options.TransportMode == ModePipe {
		r.pipeIPC = NewPipeIPC(r.identity, r.bucket.Load(), "", options.Pipes)
	}
	r.OnConfigChange(ctx, cfg)
	return r, nil
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

func (r *recordingServer) Serve(ctx context.Context) error {
	if r.TransportMode == ModePipe {
		return r.pipeIPC.Serve(ctx)
	}
	return nil
}

func (r *recordingServer) Shutdown(_ context.Context) error {
	if r.TransportMode == ModePipe {
		if err := r.pipeIPC.Close(); err != nil {
			return fmt.Errorf("session recording: failed to shutdown : %w", err)
		}
	}
	return nil
}

func (r *recordingServer) Record(stream grpc.BidiStreamingServer[recording.RecordingData, recording.RecordingCheckpoint]) error {
	if r.TransportMode != ModeGRPC {
		return status.Error(codes.FailedPrecondition, "session recording IPC mode is not gRPC")
	}
	ctx := middleware.ContextWithBlobUserAgent(stream.Context(), r.identity)
	done := make(chan struct{})
	tr := &grpcTransport{stream: stream}
	defer close(done)
	r.cfgMu.Lock()
	if len(r.grpcTransportChange) >= int(r.Concurrency) {
		r.cfgMu.Unlock()
		return status.Error(codes.ResourceExhausted, "max concurrency exceeded")
	}
	bindTransportChange := make(chan bucketConfigUpdate, 8)
	r.grpcTransportChange = append(r.grpcTransportChange, bindTransportChange)
	bk, prefix := r.bucket.Load(), r.blobCfg.Load().ManagedPrefix
	r.cfgMu.Unlock()
	defer func() {
		r.cfgMu.Lock()
		r.grpcTransportChange = slices.DeleteFunc(r.grpcTransportChange, func(t chan bucketConfigUpdate) bool { return t == bindTransportChange })
		r.cfgMu.Unlock()
	}()

	go func() {
		for {
			select {
			case <-done:
				return
			case upd := <-bindTransportChange:
				tr.OnChange(upd.bucket, upd.managedPrefix)
			}
		}
	}()
	return RunProtocol(ctx, tr, maxChunkSize, bk, prefix)
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
	switch r.TransportMode {
	case ModeGRPC:
		for _, grpcListener := range r.grpcTransportChange {
			select {
			case grpcListener <- bucketConfigUpdate{
				bucket:        r.bucket.Load(),
				managedPrefix: prefix,
			}:
			default:
				log.Ctx(ctx).Warn().Msg("grpc transport config change buffer full, could not propagate update")
			}
		}
	case ModePipe:
		log.Ctx(ctx).Debug().Msg("propagating bucket changes to pipes")
		r.pipeIPC.OnChange(r.bucket.Load(), prefix)
	}
}

var _ recording.RecordingServiceServer = (*recordingServer)(nil)
