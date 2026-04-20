package recording

import (
	"context"
	//nolint:gosec
	"crypto/md5"
	"errors"
	"fmt"
	"io"

	gblob "gocloud.dev/blob"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/storage/blob"
)

const maxChunkSize = 1024 * 1024 * 1024

var (
	ErrMissingMetadata    = errors.New("first message for a recording must contain metadata")
	ErrInvalidMetadata    = errors.New("invalid metadata")
	ErrMetadataEmpty      = errors.New("metadata any value is empty")
	ErrMissingRecordingID = errors.New("message is missing a recording id")
	ErrChunkTooLarge      = errors.New("chunk exceeds max size")
	ErrChecksumMismatch   = errors.New("checksum did not match")
	ErrSendSessionFailed  = errors.New("send session failed")
)

// TransportProtocol is the abstration that enables bi-directional communication
// between the recording server and the recording client
type TransportProtocol interface {
	Recv(ctx context.Context) (*recording.RecordingData, error)
	Send(ctx context.Context, s *recording.RecordingSession) error
}

// recordingState is the per-id slice of writer state kept by a handler.
// A single transport can interleave messages for multiple recording ids,
// so state is keyed by RecordingData.recording_id.
type recordingState struct {
	cw           blob.ChunkWriter
	metadataSent bool
	accumulated  []byte
}

type handler struct {
	bucket        *gblob.Bucket
	managedPrefix string
	states        map[string]*recordingState
}

func newHandler(bucket *gblob.Bucket, managedPrefix string) *handler {
	return &handler{
		bucket:        bucket,
		managedPrefix: managedPrefix,
		states:        make(map[string]*recordingState),
	}
}

// Step advances the protocol by one message. When a reply is due to the peer
// (handshake, per-chunk ack) the returned RecordingSession is non-nil.
func (h *handler) Step(ctx context.Context, msg *recording.RecordingData) (*recording.RecordingSession, error) {
	id := msg.GetRecordingId()
	if id == "" {
		return nil, ErrMissingRecordingID
	}

	switch d := msg.Data.(type) {
	case *recording.RecordingData_Metadata:
		return h.onMetadata(ctx, id, d.Metadata)
	case *recording.RecordingData_Chunk:
		return nil, h.onChunk(id, d.Chunk)
	case *recording.RecordingData_Checksum:
		return h.onChecksum(ctx, id, d.Checksum)
	case *recording.RecordingData_Trailer:
		return nil, h.onTrailer(ctx, id, d.Trailer)
	default:
		return nil, fmt.Errorf("unexpected recording data of type %T", msg.Data)
	}
}

// onMetadata opens (or reuses) the writer for this id, persists the incoming
// metadata, and replies with the current manifest so the client can resume
// from the correct chunk offset.
func (h *handler) onMetadata(ctx context.Context, id string, md *recording.RecordingMetadata) (*recording.RecordingSession, error) {
	if err := validateMetadata(md); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidMetadata, err)
	}
	st, err := h.openWriter(ctx, id, md.GetRecordingType())
	if err != nil {
		return nil, err
	}
	if err := st.cw.WriteMetadata(ctx, md); err != nil {
		return nil, err
	}
	st.metadataSent = true
	return &recording.RecordingSession{Manifest: st.cw.CurrentManifest()}, nil
}

func (h *handler) onChunk(id string, data []byte) error {
	if err := checkLimits(data); err != nil {
		return err
	}
	st, ok := h.states[id]
	if !ok || !st.metadataSent {
		return ErrMissingMetadata
	}
	st.accumulated = append(st.accumulated, data...)
	return nil
}

func (h *handler) onChecksum(ctx context.Context, id string, checksum []byte) (*recording.RecordingSession, error) {
	st, ok := h.states[id]
	if !ok || !st.metadataSent {
		return nil, ErrMissingMetadata
	}
	var incoming [16]byte
	copy(incoming[:], checksum)
	//nolint:gosec
	actual := md5.Sum(st.accumulated)
	if actual != incoming {
		return nil, ErrChecksumMismatch
	}

	if err := st.cw.WriteChunk(ctx, st.accumulated, incoming); err != nil {
		return nil, err
	}
	st.accumulated = st.accumulated[:0]
	return &recording.RecordingSession{Manifest: st.cw.CurrentManifest()}, nil
}

func (h *handler) onTrailer(ctx context.Context, id string, trailer *recording.RecordingTrailer) error {
	st, ok := h.states[id]
	if !ok {
		return ErrMissingMetadata
	}
	if err := st.cw.Finalize(ctx, trailer); err != nil {
		return err
	}
	delete(h.states, id)
	return nil
}

// openWriter lazily opens aCchunkWriter
func (h *handler) openWriter(ctx context.Context, id string, fmtType recording.RecordingFormat) (*recordingState, error) {
	if st, ok := h.states[id]; ok {
		return st, nil
	}
	cw, err := blob.NewChunkWriter(ctx, blob.SchemaV1WithKey{
		SchemaV1: blob.SchemaV1{
			ClusterID:     h.managedPrefix,
			RecordingType: string(convertFormat(fmtType)),
		},
		Key: id,
	}, h.bucket)
	if err != nil {
		return nil, err
	}
	st := &recordingState{
		cw:           cw,
		metadataSent: cw.CurrentMetadata() != nil,
	}
	h.states[id] = st
	return st, nil
}

// RunProtocol processes session-recording messages arriving on a single
// transport and writes replies back on the same transport when a message
// requires an acknowledgement
//
// One transport can carry many recordings concurrently. Every message is
// tagged with its recording ID
//
// For a given ID the expected sequence is:
//
//  1. Metadata. The server reconciles it against the blob store and replies
//     with the current chunk manifest, which the client uses to resume from
//     the correct offset
//  2. Zero or more chunks, each followed by a checksum. When the checksum
//     matches, the server uploads the accumulated bytes and returns the
//     updated manifest
//  3. A trailer, which finalizes the recording
func RunProtocol(ctx context.Context, t TransportProtocol, bucket *gblob.Bucket, managedPrefix string) error {
	h := newHandler(bucket, managedPrefix)
	for {
	RETRY:
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		msg, err := t.Recv(ctx)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			log.Ctx(ctx).Err(err).Msg("failed to receive message from session recording client")
			goto RETRY
		}
		resp, err := h.Step(ctx, msg)
		if err != nil {
			log.Ctx(ctx).Err(err).Str("recording-id", msg.GetRecordingId()).Msg("session recording message processing failed")
			goto RETRY
		}
		if resp != nil {
			if err := t.Send(ctx, resp); err != nil {
				log.Ctx(ctx).Err(err).Str("recording-id", msg.GetRecordingId()).Msg("failed to send response to session recording metadata client")
			}
		}
	}
}

func validateMetadata(md *recording.RecordingMetadata) error {
	if md == nil {
		return fmt.Errorf("metadata is nil")
	}
	if md.GetRecordingType() == recording.RecordingFormat_RecordingFormatUnknown {
		return fmt.Errorf("invalid recording type: %s", md.GetRecordingType().String())
	}

	if md.GetMetadata().GetValue() == nil {
		return fmt.Errorf("metadata value is empty")
	}
	return nil
}

func checkLimits(chunk []byte) error {
	if len(chunk) > maxChunkSize {
		return ErrChunkTooLarge
	}
	return nil
}

func convertFormat(rfmt recording.RecordingFormat) blob.RecordingType {
	switch rfmt {
	case recording.RecordingFormat_RecordingFormatSSH:
		return blob.RecordingTypeSSH
	default:
		panic(fmt.Sprintf("unhandled recording format : %s", rfmt.String()))
	}
}

func statusFromProtocolErr(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := status.FromError(err); ok {
		// return existing grpc error
		return err
	}
	switch {
	case errors.Is(err, ErrMissingMetadata),
		errors.Is(err, blob.ErrChunkGap),
		errors.Is(err, blob.ErrMetadataMismatch),
		errors.Is(err, blob.ErrChunkWriteConflict),
		errors.Is(err, blob.ErrAlreadyFinalized):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, ErrInvalidMetadata),
		errors.Is(err, ErrMetadataEmpty),
		errors.Is(err, ErrMissingRecordingID):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ErrChunkTooLarge):
		return status.Error(codes.Aborted, err.Error())
	case errors.Is(err, ErrChecksumMismatch):
		return status.Error(codes.DataLoss, err.Error())
	case errors.Is(err, ErrSendSessionFailed):
		return status.Error(codes.Internal, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}
