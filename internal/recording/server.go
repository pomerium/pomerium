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

func (r *recordingServer) Record(stream grpc.BidiStreamingServer[recording.RecordingData, recording.RecordingSession]) error {
	ctx := stream.Context()
	if !r.sem.TryAcquire() {
		return status.Error(codes.ResourceExhausted, "max concurrency exceeded")
	}
	defer r.sem.Release()

	bucket, srvCfg, prefix, bucketErr := r.loadStreamConfig()
	if bucketErr != nil {
		return status.Error(codes.Unavailable, fmt.Sprintf("failed to load bucket from configuration: %s", bucketErr))
	}

	log.Ctx(ctx).Debug().Msg("processing recording metadata")
	cw, err := handleMetadataHandshake(ctx, bucket, srvCfg, prefix, stream)
	if err != nil {
		log.Ctx(ctx).Err(err).Msg("failed to process recording metadata")
		return err
	}

	eg, eCtx := errgroup.WithContext(ctx)

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
		return writeStep(eCtx, cw, pipe, stream, srvCfg)
	})
	// recv chunks from client
	eg.Go(func() error {
		defer close(pipe)
		return recvStep(eCtx, cw, recvCh, pipe, srvCfg)
	})
	uploadErr := eg.Wait()
	if uploadErr != nil {
		log.Ctx(ctx).Err(uploadErr).Msg("failed to upload blob")
	}
	return uploadErr
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

func validateMetadata(rmd *recording.RecordingMetadata) error {
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

func handleMetadataHandshake(
	ctx context.Context,
	bucket *gblob.Bucket,
	srvConfig *recording.ServerConfig,
	managedPrefix string,
	stream grpc.BidiStreamingServer[recording.RecordingData, recording.RecordingSession],
) (blob.ChunkWriter, error) {
	msg, err := stream.Recv()
	if err != nil {
		return nil, err
	}
	md := msg.GetMetadata()
	if md == nil {
		return nil, status.Error(codes.FailedPrecondition, "first message should contain metadata")
	}
	if err := validateMetadata(md); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	mdBytes := md.GetMetadata().GetValue()
	if mdBytes == nil {
		return nil, status.Error(codes.InvalidArgument, "metadata any value is empty")
	}

	cw, err := writeMetadata(ctx, md, managedPrefix, bucket)
	if err != nil {
		return nil, err
	}

	if err := stream.Send(&recording.RecordingSession{
		Config:   srvConfig,
		Manifest: cw.CurrentManifest(),
	}); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to send recording session information to client : %s", err))
	}
	return cw, nil
}

func writeMetadata(
	ctx context.Context,
	md *recording.RecordingMetadata,
	managedPrefix string,
	bucket *gblob.Bucket,
) (blob.ChunkWriter, error) {
	cw, err := blob.NewChunkWriter(ctx, blob.SchemaV1WithKey{
		SchemaV1: blob.SchemaV1{
			ClusterID:     managedPrefix,
			RecordingType: string(convertFormat(md.GetRecordingType())),
		},
		Key: md.GetId(),
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

func writeStep(
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

func recvStep(
	ctx context.Context,
	cw blob.ChunkWriter,
	recv chan recvResult,
	send chan AccumulatedChunk,
	srvCfg *recording.ServerConfig,
) error {
	var accumulated []byte
	inFlightChunks := 0
	for {
		msg, err := handleClientMsg(ctx, recv)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}

		switch recvData := msg.Data.(type) {
		case *recording.RecordingData_Chunk:
			inFlightChunks++
			if err := checkLimits(recvData.Chunk, srvCfg, inFlightChunks); err != nil {
				return err
			}
			accumulated = append(accumulated, recvData.Chunk...)

		case *recording.RecordingData_Checksum:
			if err := sendWithWaitAndCancel(ctx, accumulated, [16]byte(recvData.Checksum), send); err != nil {
				return err
			}
			// reset in-flight chunks
			accumulated = []byte{}
			inFlightChunks = 0
		case *recording.RecordingData_Sig:
			return writeSignature(ctx, cw, recvData)
		}
	}
}

func handleClientMsg(ctx context.Context, recv chan recvResult) (*recording.RecordingData, error) {
	var rr recvResult
	select {
	case r, ok := <-recv:
		if !ok {
			return nil, io.EOF
		}
		rr = r
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if rr.err != nil {
		return nil, rr.err
	}
	return rr.msg, nil
}

func checkLimits(chunk []byte, srvCfg *recording.ServerConfig, inflight int) error {
	if len(chunk) > int(srvCfg.MaxChunkSize) {
		return status.Error(codes.Aborted, "client sent a chunk whose size exceeded the maximum set by the server")
	}
	if inflight > int(srvCfg.MaxChunkBatchNum) {
		return status.Error(codes.Aborted, "client exceeded maximum in-flight number of chunks")
	}
	return nil
}

func sendWithWaitAndCancel(
	ctx context.Context,
	data []byte,
	incomingChecksum [16]byte,
	send chan AccumulatedChunk,
) error {
	//nolint:gosec
	actual := md5.Sum(data)
	if actual != incomingChecksum {
		err := status.Error(codes.DataLoss, "checksum did not match")
		log.Ctx(ctx).Err(err).Msg("checksum did not match")
		return err
	}
	select {
	case send <- AccumulatedChunk{
		checksum: incomingChecksum,
		data:     data,
	}:
		log.Ctx(ctx).Debug().Int("size", len(data)).Msg("sent chunk to blob writer")
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func writeSignature(ctx context.Context, cw blob.ChunkWriter, data *recording.RecordingData_Sig) error {
	sigErr := cw.Finalize(ctx, data.Sig)
	if errors.Is(sigErr, blob.ErrAlreadyFinalized) {
		return status.Error(codes.FailedPrecondition, "already signed")
	} else if sigErr != nil {
		return status.Error(codes.Internal, sigErr.Error())
	}
	return nil
}

type recvResult struct {
	msg *recording.RecordingData
	err error
}

func (r *recordingServer) loadStreamConfig() (bucket *gblob.Bucket, srvCfg *recording.ServerConfig, prefix string, err error) {
	r.cfgMu.RLock()
	defer r.cfgMu.RUnlock()
	return r.bucket.Load(), r.serverConfig(), r.blobCfg.Load().ManagedPrefix, r.bucketErr
}

var _ recording.RecordingServiceServer = (*recordingServer)(nil)
