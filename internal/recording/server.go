package recording

import (
	"context"
	//nolint:gosec
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	gblob "gocloud.dev/blob"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/health"
	"github.com/pomerium/pomerium/pkg/storage/blob"
	"github.com/pomerium/pomerium/pkg/storage/blob/providers"
)

type Server interface {
	OnConfigChange(ctx context.Context, cfg *config.Config)
	recording.RecordingServiceServer
}

func convertFormat(rfmt recording.RecordingFormat) blob.RecordingType {
	switch rfmt {
	case recording.RecordingFormat_RecordingFormatSSH:
		return blob.RecordingTypeSSH
	default:
		panic(fmt.Sprintf("unhandled recording format : %s", rfmt.String()))
	}
}

type recordingServer struct {
	recording.UnsafeRecordingServiceServer

	sem *dynamicSemaphore

	cfgMu sync.RWMutex

	blobCfg   atomic.Pointer[blob.StorageConfig]
	config    atomic.Pointer[config.RecordingServerConfig]
	bucket    atomic.Pointer[gblob.Bucket]
	bucketErr error
}

func NewRecordingServer(ctx context.Context, cfg *config.Config) Server {
	limit := 8
	if cfg.Options.RecordingServerConfig != nil {
		limit = cfg.Options.RecordingServerConfig.MaxConcurrentStreams
	}

	r := &recordingServer{
		bucketErr: fmt.Errorf("not intiialized"),
		bucket:    atomic.Pointer[gblob.Bucket]{},
		sem:       newDynamicSemaphore(limit),
		config:    atomic.Pointer[config.RecordingServerConfig]{},
	}
	r.config.Store(cfg.Options.RecordingServerConfig)
	r.OnConfigChange(ctx, cfg)
	return r
}

func (r *recordingServer) serverConfig() *recording.ServerConfig {
	cfg := r.config.Load()
	if cfg == nil {
		return &recording.ServerConfig{
			MaxStreams:       8,
			MaxChunkBatchNum: 6,
			MaxChunkSize:     16 * 1024 * 1024,
		}
	}

	return &recording.ServerConfig{
		MaxStreams:       uint32(cfg.MaxConcurrentStreams),
		MaxChunkBatchNum: uint32(cfg.MaxChunkBatchNum),
		MaxChunkSize:     uint32(cfg.MaxChunkSize),
	}
}

func (r *recordingServer) handleRecordingServerChange(cfg *config.RecordingServerConfig) {
	r.config.Store(cfg)

	if cfg != nil {
		r.sem.Resize(cfg.MaxConcurrentStreams)
	}
}

func (r *recordingServer) handleBlobChange(ctx context.Context, cfg *blob.StorageConfig) {
	curCfg := r.blobCfg.Load()
	configDifferent := curCfg != nil && curCfg.BucketURI != cfg.BucketURI
	hasConfigChanged := (curCfg == nil) || curCfg.BucketURI != cfg.BucketURI
	if configDifferent {
		if bk := r.bucket.Load(); bk != nil {
			if err := bk.Close(); err != nil {
				log.Ctx(ctx).Err(err).Msg("failed to close pre-existing bucket")
			}
		}
	}
	if hasConfigChanged {
		bucket, err := providers.OpenBucket(ctx, cfg.BucketURI)
		if err != nil {
			health.ReportError(health.BlobStorage, err)
			r.bucketErr = err
			r.bucket.Store(nil)
		} else {
			r.bucket.Store(bucket)
			r.bucketErr = nil
			health.ReportRunning(health.BlobStorage)
		}
	}

	if cfg == nil {
		r.bucket.Store(nil)
		r.bucketErr = fmt.Errorf("blob storage configuration is not set")
	}
}

func (r *recordingServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	r.cfgMu.Lock()
	defer r.cfgMu.Unlock()
	r.handleRecordingServerChange(cfg.Options.RecordingServerConfig)
	r.handleBlobChange(ctx, cfg.Options.BlobStorage)
	// propagate changes to server once the new bucket is opened and not before
	r.blobCfg.Store(cfg.Options.BlobStorage)
}

func (r *recordingServer) validateMetadata(rmd *recording.RecordingMetadata) error {
	if rmd.Id == "" {
		return fmt.Errorf("id must not be empty")
	}
	if rmd.RecordingType == recording.RecordingFormat_RecordingFormatUnknown {
		return fmt.Errorf("invalid recording type : %s", rmd.RecordingType.String())
	}
	return nil
}

type AccumulatedChunk struct {
	// md5 checksum
	checksum [16]byte
	data     []byte
}

func (r *recordingServer) handleMetadataHandshake(ctx context.Context, md *recording.RecordingMetadata, bucket *gblob.Bucket) (blob.ChunkWriter, error) {
	if md == nil {
		return nil, status.Error(codes.FailedPrecondition, "first message should contain metadata")
	}
	if err := r.validateMetadata(md); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	mdBytes := md.GetMetadata().GetValue()
	if mdBytes == nil {
		return nil, status.Error(codes.InvalidArgument, "metadata any value is empty")
	}

	recordingID := md.GetId()
	cw, err := blob.NewChunkWriter(ctx, blob.SchemaV1WithKey{
		SchemaV1: blob.SchemaV1{
			ClusterID:     r.blobCfg.Load().ManagedPrefix,
			RecordingType: string(convertFormat(md.GetRecordingType())),
		},
		Key: recordingID,
	}, bucket)

	if errors.Is(err, blob.ErrChunkGap) || errors.Is(err, blob.ErrAlreadyFinalized) {
		return nil, status.Error(codes.FailedPrecondition, "writer conflict")
	} else if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	mdErr := cw.WriteMetadata(ctx, md)
	if errors.Is(mdErr, blob.ErrMetadataMismatch) {
		return nil, status.Error(codes.FailedPrecondition, "metadata conflict")
	} else if mdErr != nil {
		return nil, status.Error(codes.Internal, mdErr.Error())
	}
	return cw, nil
}

func (r *recordingServer) writeStep(
	ctx context.Context,
	cw blob.ChunkWriter,
	pipe chan AccumulatedChunk,
	stream grpc.BidiStreamingServer[recording.RecordingData, recording.RecordingSession],
	srvCfg *recording.ServerConfig,
) error {
	for {
		select {
		case data, ok := <-pipe:
			if !ok {
				log.Ctx(ctx).Debug().Msg("writing is done")
				return nil
			}
			log.Ctx(ctx).Debug().Int("size", len(data.data)).Msg("received data to write")
			writeErr := cw.WriteChunk(ctx, data.data, data.checksum)
			if errors.Is(writeErr, blob.ErrChunkWriteConflict) || errors.Is(writeErr, blob.ErrAlreadyFinalized) {
				return status.Error(codes.FailedPrecondition, "chunk conflict")
			}
			if writeErr != nil {
				return status.Error(codes.Internal, fmt.Sprintf("failed to write chunk : %s", writeErr))
			}

			log.Ctx(ctx).Debug().Msg("sending client info about current recording")
			if err := stream.Send(&recording.RecordingSession{
				Config:   srvCfg,
				Manifest: cw.CurrentManifest(),
			}); err != nil {
				return status.Error(codes.Internal, fmt.Sprintf("failed to send recording session information to client : %s", err))
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (r *recordingServer) recvStep(
	ctx context.Context,
	cw blob.ChunkWriter,
	recv chan recvResult,
	send chan AccumulatedChunk,
	srvCfg *recording.ServerConfig,
) error {
	var accumulated []byte
	inFlightChunks := 0
	for {
		var rr recvResult
		select {
		case r, ok := <-recv:
			if !ok {
				return nil
			}
			rr = r
		case <-ctx.Done():
			return ctx.Err()
		}
		if errors.Is(rr.err, io.EOF) {
			return nil
		}
		if rr.err != nil {
			return rr.err
		}
		switch recvData := rr.msg.Data.(type) {
		case *recording.RecordingData_Chunk:
			if len(recvData.Chunk) > int(srvCfg.MaxChunkSize) {
				return status.Error(codes.Aborted, "client sent a chunk whose size exceeded the maximum set by the server")
			}
			inFlightChunks++
			if inFlightChunks > int(srvCfg.MaxChunkBatchNum) {
				return status.Error(codes.Aborted, "client exceeded maximum in-flight number of chunks")
			}
			accumulated = append(accumulated, recvData.Chunk...)

		case *recording.RecordingData_Checksum:
			//nolint:gosec
			actual := md5.Sum(accumulated)
			recvCheckSum := [16]byte(recvData.Checksum)
			if actual != recvCheckSum {
				err := status.Error(codes.DataLoss, "checksum did not match")
				log.Ctx(ctx).Err(err).Msg("checksum did not match")
				return err
			}
			select {
			case send <- AccumulatedChunk{
				checksum: recvCheckSum,
				data:     accumulated,
			}:
				log.Ctx(ctx).Debug().Int("size", len(accumulated)).Msg("sent chunk to blob writer")
				accumulated = []byte{}
				inFlightChunks = 0
			case <-ctx.Done():
				return ctx.Err()
			}
		case *recording.RecordingData_Sig:
			sigErr := cw.Finalize(ctx, recvData.Sig)
			if errors.Is(sigErr, blob.ErrAlreadyFinalized) {
				return status.Error(codes.FailedPrecondition, "already signed")
			} else if sigErr != nil {
				return status.Error(codes.Internal, sigErr.Error())
			}
		}
	}
}

type recvResult struct {
	msg *recording.RecordingData
	err error
}

func (r *recordingServer) Record(stream grpc.BidiStreamingServer[recording.RecordingData, recording.RecordingSession]) error {
	ctx := stream.Context()
	if !r.sem.TryAcquire() {
		return status.Error(codes.ResourceExhausted, "max concurrency exceeded")
	}
	defer r.sem.Release()

	r.cfgMu.RLock()
	bucketErr := r.bucketErr
	srvCfg := r.serverConfig()
	bucket := r.bucket.Load()
	r.cfgMu.RUnlock()
	if bucketErr != nil {
		return status.Error(codes.Unavailable, fmt.Sprintf("failed to load bucket from configuration: %s", bucketErr))
	}
	log.Ctx(ctx).Debug().Msg("received new recording request")

	// === expect metadata ===
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	md := msg.GetMetadata()
	logger := log.Ctx(ctx).With().Str("recording-id", md.GetId()).Logger()
	logger.Debug().Msg("processing recording metadata")
	cw, err := r.handleMetadataHandshake(ctx, md, bucket)
	if err != nil {
		logger.Err(err).Msg("failed to process recording metadata")
		return err
	}

	logger.Debug().Msg("sending client info about current recording")
	if err := stream.Send(&recording.RecordingSession{
		Config:   r.serverConfig(),
		Manifest: cw.CurrentManifest(),
	}); err != nil {
		return status.Error(codes.Internal, fmt.Sprintf("failed to send recording session information to client : %s", err))
	}

	eg, eCtx := errgroup.WithContext(ctx)
	eCtx = logger.WithContext(eCtx)

	recvCh := make(chan recvResult, 1)
	// prevents blocking the errgroup on messages from remote
	go func() {
		defer close(recvCh)
		for {
			msg, err := stream.Recv()
			select {
			case recvCh <- recvResult{msg, err}:
			case <-eCtx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()

	pipe := make(chan AccumulatedChunk, 1)
	// upload chunks to remote
	eg.Go(func() error {
		return r.writeStep(eCtx, cw, pipe, stream, srvCfg)
	})
	// recv chunks from client
	eg.Go(func() error {
		defer close(pipe)
		return r.recvStep(eCtx, cw, recvCh, pipe, srvCfg)
	})
	uploadErr := eg.Wait()
	if uploadErr != nil {
		logger.Err(uploadErr).Msg("failed to upload blob")
	}
	return uploadErr
}

var _ recording.RecordingServiceServer = (*recordingServer)(nil)
