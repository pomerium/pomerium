package recording

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/semaphore"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/recording"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/storage/blob"
	"github.com/pomerium/pomerium/pkg/storage/blob/providers"
)

const (
	defaultMaxStreamConcurrency uint32 = 8
)

type Server interface {
	OnConfigChange(ctx context.Context, cfg *config.Config)
	recording.RecordingServiceServer
}

type recordingServer struct {
	store blob.ObjectReaderWriter
	recording.UnsafeRecordingServiceServer

	mu             sync.RWMutex
	maxStreams     *semaphore.Weighted
	maxStreamCount uint32
	config.RecordingServerConfig
	bucketErr error
}

func NewRecordingServer(ctx context.Context, cfg *config.Config, prefix string, blobOpts ...blob.Option) Server {
	// anypb is a sentinel type, it isn't used anywhere
	store := blob.NewStore[anypb.Any](ctx, prefix, blobOpts...)

	maxStreams := defaultMaxStreamConcurrency
	if cfg.Options.RecordingServerConfig != nil && cfg.Options.RecordingServerConfig.MaxConcurrentStreams > 0 {
		maxStreams = cfg.Options.RecordingServerConfig.MaxConcurrentStreams
	}

	r := &recordingServer{
		bucketErr:      nil,
		mu:             sync.RWMutex{},
		store:          store.ReaderWriter(),
		maxStreams:     semaphore.NewWeighted(int64(maxStreams)),
		maxStreamCount: maxStreams,
	}
	r.OnConfigChange(ctx, cfg)
	return r
}

func (r *recordingServer) serverConfig() *recording.ServerConfig {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return &recording.ServerConfig{
		MaxStreams:       r.maxStreamCount,
		MaxChunkBatchNum: r.MaxChunkBatchNum,
		MaxChunkSize:     r.MaxChunkSize,
	}
}

func (r *recordingServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cfg.Options.RecordingServerConfig != nil {
		r.RecordingServerConfig = *cfg.Options.RecordingServerConfig
	}
	if cfg.Options.BlobStorage == nil {
		return
	}
	provider := cfg.Options.BlobStorage.Provider
	store, err := providers.NewBucketFromConfig(cfg.Options.BlobStorage)
	if err != nil {
		log.Ctx(ctx).Err(err).Msg("failed to load bucket from config")
		r.bucketErr = err
		health.ReportError(health.BlobStore, err, health.StrAttr("provider", provider))
		return
	}
	r.bucketErr = nil
	health.ReportRunning(health.BlobStore, health.StrAttr("provider", provider))
	r.store.OnConfigChange(ctx, store)
}

// TODO : put this in buf.validation rules?
func (r *recordingServer) validateMetadata(rmd *recording.RecordingMetadata) error {
	if rmd.Id == "" {
		return fmt.Errorf("id must not be empty")
	}
	if rmd.RecordingType == "" {
		return fmt.Errorf("recording type must not be empty")
	}
	return nil
}

type AccumulatedChunk struct {
	checksum [32]byte
	data     []byte
}

func (r *recordingServer) Record(stream grpc.BidiStreamingServer[recording.RecordingData, recording.RecordingSession]) error {
	ctx := stream.Context()
	if !r.maxStreams.TryAcquire(1) {
		log.Ctx(ctx).Warn().Msg("max streams exceeded")
		return status.Error(codes.ResourceExhausted, fmt.Sprintf("max streams exceeded: %d", r.maxStreamCount))
	}
	defer r.maxStreams.Release(1)
	r.mu.RLock()
	if r.bucketErr != nil {
		log.Ctx(ctx).Err(r.bucketErr).Msg("failed to load bucket from configuration")
		return status.Error(codes.Internal, fmt.Sprintf("failed to load bucket from configuration: %s", r.bucketErr))
	}
	r.mu.RUnlock()

	log.Ctx(ctx).Debug().Msg("received new recording request")

	// === Metadata ===
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	md := msg.GetMetadata()
	if md == nil {
		return status.Error(codes.FailedPrecondition, "first message should contain metadata")
	}
	if err := r.validateMetadata(md); err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	logger := log.Ctx(ctx).With().Str("recording-id", md.GetId()).Logger()
	logger.Info().Msg("processing recording")

	// == Acquire chunk writer ==
	prefix := md.GetRecordingType()
	id := md.GetId()
	mdBytes := md.GetMetadata().GetValue()
	if mdBytes == nil {
		return status.Error(codes.InvalidArgument, "metadata any value is empty")
	}

	eg, eCtx := errgroup.WithContext(ctx)
	logger.Debug().Msg("opening bucket for streaming")
	// FIXME: the impl currently overwrites metadata whenever we acquire the chunk writer
	cw, err := r.store.Start(eCtx, prefix, id, bytes.NewReader(mdBytes))
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	// == Send manifest to remote ==
	logger.Debug().Msg("sending info of current recording")
	if err := stream.Send(&recording.RecordingSession{
		Config:   r.serverConfig(),
		Manifest: cw.CurrentManifest(),
	}); err != nil {
		return status.Error(codes.Internal, fmt.Sprintf("failed to send recording session information to client : %s", err))
	}

	// == handle streamed data ==
	pipe := make(chan AccumulatedChunk, 1)
	eg.Go(func() error {
		for {
			select {
			case data, ok := <-pipe:
				if !ok {
					log.Ctx(ctx).Debug().Msg("writing is done")
					return nil
				}
				log.Ctx(ctx).Debug().Int("size", len(data.data)).Msg("received data to write")
				if err := cw.WriteChunk(eCtx, data.data, data.checksum); err != nil {
					return status.Error(codes.Internal, fmt.Sprintf("failed to write chunk : %s", err))
				}

				// == Send manifest to remote ==
				logger.Debug().Msg("sending info of current recording")
				if err := stream.Send(&recording.RecordingSession{
					Config:   r.serverConfig(),
					Manifest: cw.CurrentManifest(),
				}); err != nil {
					return status.Error(codes.Internal, fmt.Sprintf("failed to send recording session information to client : %s", err))
				}
			case <-eCtx.Done():
				return eCtx.Err()
			}
		}
	})
	eg.Go(func() error {
		defer close(pipe)
		var accumulated []byte
		inFlightChunks := 0
		for {
			msg, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return err
			}
			switch recvData := msg.Data.(type) {
			case *recording.RecordingData_Chunk:
				accumulated = append(accumulated, recvData.Chunk...)
				inFlightChunks++
				srvConfig := r.serverConfig()
				if inFlightChunks > int(srvConfig.MaxChunkBatchNum) {
					return status.Error(codes.Aborted, "client exceeded maximum in flight number chunks")
				}

			case *recording.RecordingData_Checksum:
				actual := sha256.Sum256(accumulated)
				recvCheckSum := [32]byte(recvData.Checksum)
				if actual != recvCheckSum {
					err := status.Error(codes.FailedPrecondition, "checksum did not match")
					logger.Err(err).Msg("checksum did not match")
					return err
				}
				select {
				case pipe <- AccumulatedChunk{
					checksum: recvCheckSum,
					data:     accumulated,
				}:
					log.Ctx(ctx).Debug().Int("size", len(accumulated)).Msg("sent chunk to blob writer")
					accumulated = []byte{}
					inFlightChunks = 0
				case <-eCtx.Done():
					return eCtx.Err()
				}
			}
		}
	})

	return eg.Wait()
}

var _ recording.RecordingServiceServer = (*recordingServer)(nil)
