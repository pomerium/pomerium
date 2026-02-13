package recording

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc/recording"
	"github.com/pomerium/pomerium/pkg/storage/blob"
)

type Server interface {
	OnConfigChange(ctx context.Context, cfg *config.Config)
	recording.RecordingServiceServer
}

type recordingServer struct {
	store blob.ObjectReaderWriter
	recording.UnsafeRecordingServiceServer
}

func NewRecordingServer(ctx context.Context, cfg *config.Config, prefix string) Server {
	// anypb is a sentinel
	store := blob.NewStore[anypb.Any](ctx, prefix, blob.WithIncludeInstallationID())

	r := &recordingServer{
		store: store.ReaderWriter(),
	}
	r.OnConfigChange(ctx, cfg)
	return r
}

func (r *recordingServer) OnConfigChange(ctx context.Context, cfg *config.Config) {
	r.store.OnConfigChange(ctx, cfg)
}

func (r *recordingServer) validateMetadata(rmd *recording.RecordingMetadata) error {
	if rmd.Id == "" {
		return fmt.Errorf("id must not be empty")
	}
	return nil
}

// TODO : I think I'd like to extract decompression method from grpc metatada here
func (r *recordingServer) Record(stream grpc.ClientStreamingServer[recording.RecordingData, emptypb.Empty]) error {
	ctx := stream.Context()

	log.Ctx(ctx).Debug().Msg("received new recording request")

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

	// TODO : verify if we are restarting from a previous checkpoint that was interrupted

	mdBytes, err := proto.Marshal(md.GetMetadata())
	if err != nil {
		return status.Error(codes.Internal, fmt.Sprintf("marshal metadata: %v", err))
	}

	pr, pw := io.Pipe()

	eg, eCtx := errgroup.WithContext(ctx)
	eg.Go(func() error {
		defer pr.Close()
		// TODO : do we want to set a deadline here?
		if err := r.store.Put(eCtx, md.GetId(), bytes.NewReader(mdBytes), pr); err != nil {
			return status.Error(codes.Internal, err.Error())
		}
		return nil
	})
	eg.Go(func() error {
		defer pw.Close()
		var accumulated []byte
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
			case *recording.RecordingData_Checksum:
				actual := sha256.Sum256(accumulated)
				if actual != [32]byte(recvData.Checksum) {
					err := status.Error(codes.FailedPrecondition, "checksum did not match")
					logger.Err(err).Msg("checksum did not match")
					return err
				}
				// FIXME: decoding compressed data won't work here
				if _, err := pw.Write(accumulated); err != nil {
					logger.Err(err).Msg("failed to write to buffer")
					return err
				}
				accumulated = []byte{}
			}
		}
	})
	return eg.Wait()
}

var _ recording.RecordingServiceServer = (*recordingServer)(nil)
