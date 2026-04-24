package recording

import (
	"context"
	//nolint:gosec
	"crypto/md5"
	"errors"
	"fmt"
	"io"

	gblob "gocloud.dev/blob"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

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
)

// TransportProtocol is the abstration that enables bi-directional communication
// between the recording server and the recording client.
// This interface is specific to the server implementation
type TransportProtocol interface {
	Recv(ctx context.Context) (*recording.RecordingData, error)
	Send(ctx context.Context, s *recording.RecordingCheckpoint) error
	OnChange(bucket *gblob.Bucket, managedPrefix string)
	currentConfig() (bucket *gblob.Bucket, managedPrefix string)
}

// recordingState is the per-id slice of writer state kept by a handler.
// A single transport can interleave messages for multiple recording ids,
// so state is keyed by recording_id.
type recordingState struct {
	cw           blob.ChunkWriter
	metadataSent bool
	accumulated  []byte
}

type Handler struct {
	bucket        *gblob.Bucket
	managedPrefix string
	states        map[string]*recordingState
}

func newHandler(bucket *gblob.Bucket, managedPrefix string) *Handler {
	return &Handler{
		bucket:        bucket,
		managedPrefix: managedPrefix,
		states:        make(map[string]*recordingState),
	}
}

func (h *Handler) OnChange(bucket *gblob.Bucket, managedPrefix string) {
	if h.bucket == bucket && h.managedPrefix == managedPrefix {
		return
	}
	h.bucket = bucket
	h.managedPrefix = managedPrefix
	clear(h.states)
}

// Implements the recording protocol
func (h *Handler) Step(ctx context.Context, msg *recording.RecordingData) (*recording.RecordingCheckpoint, error) {
	id := msg.GetRecordingId()
	if id == "" {
		return &recording.RecordingCheckpoint{
			Status: errorStatus(ErrMissingRecordingID),
		}, nil
	}

	switch d := msg.Data.(type) {
	case *recording.RecordingData_Metadata:
		return h.onMetadata(ctx, id, d.Metadata), nil
	case *recording.RecordingData_Chunk:
		return h.onChunk(id, d.Chunk), nil
	case *recording.RecordingData_Checksum:
		return h.onChecksum(ctx, id, d.Checksum), nil
	case *recording.RecordingData_Trailer:
		return h.onTrailer(ctx, id, d.Trailer), nil
	default:
		return nil, fmt.Errorf("unexpected recording data of type %T", msg.Data)
	}
}

func (h *Handler) onMetadata(ctx context.Context, id string, md *recording.RecordingMetadata) *recording.RecordingCheckpoint {
	if err := validateMetadata(md); err != nil {
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(err)}
	}
	st, err := h.openWriter(ctx, id, md.GetRecordingType())
	if err != nil {
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(err)}
	}
	if err := st.cw.WriteMetadata(ctx, md); err != nil {
		return &recording.RecordingCheckpoint{
			RecordingId: id,
			Manifest:    st.cw.CurrentManifest(),
			Status:      errorStatus(err),
		}
	}
	st.metadataSent = true
	return &recording.RecordingCheckpoint{RecordingId: id, Manifest: st.cw.CurrentManifest()}
}

func (h *Handler) onChunk(id string, data []byte) *recording.RecordingCheckpoint {
	if err := checkLimits(data); err != nil {
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(err)}
	}
	st, ok := h.states[id]
	if !ok || !st.metadataSent {
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(ErrMissingMetadata)}
	}
	st.accumulated = append(st.accumulated, data...)
	return nil
}

func (h *Handler) onChecksum(ctx context.Context, id string, checksum []byte) *recording.RecordingCheckpoint {
	st, ok := h.states[id]
	if !ok || !st.metadataSent {
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(ErrMissingMetadata)}
	}
	var incoming [16]byte
	copy(incoming[:], checksum)
	//nolint:gosec
	actual := md5.Sum(st.accumulated)
	if actual != incoming {
		return &recording.RecordingCheckpoint{
			RecordingId: id,
			Manifest:    st.cw.CurrentManifest(),
			Status:      errorStatus(ErrChecksumMismatch),
		}
	}
	if err := st.cw.WriteChunk(ctx, st.accumulated, incoming); err != nil {
		return &recording.RecordingCheckpoint{
			RecordingId: id,
			Manifest:    st.cw.CurrentManifest(),
			Status:      errorStatus(err),
		}
	}
	st.accumulated = st.accumulated[:0]
	return &recording.RecordingCheckpoint{RecordingId: id, Manifest: st.cw.CurrentManifest()}
}

func (h *Handler) onTrailer(ctx context.Context, id string, trailer *recording.RecordingTrailer) *recording.RecordingCheckpoint {
	st, ok := h.states[id]
	if !ok {
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(ErrMissingMetadata)}
	}
	if err := st.cw.Finalize(ctx, trailer); err != nil {
		return &recording.RecordingCheckpoint{
			RecordingId: id,
			Manifest:    st.cw.CurrentManifest(),
			Status:      errorStatus(err),
		}
	}
	manifest := st.cw.CurrentManifest()
	delete(h.states, id)
	return &recording.RecordingCheckpoint{RecordingId: id, Manifest: manifest}
}

// openWriter lazily opens aCchunkWriter
func (h *Handler) openWriter(ctx context.Context, id string, fmtType recording.RecordingFormat) (*recordingState, error) {
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

// TODO : documentation
func RunProtocol(ctx context.Context, t TransportProtocol, bucket *gblob.Bucket, managedPrefix string) error {
	h := newHandler(bucket, managedPrefix)
	t.OnChange(bucket, managedPrefix)
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
		h.OnChange(t.currentConfig())
		resp, err := h.Step(ctx, msg)
		if err != nil {
			log.Ctx(ctx).Err(err).Str("recording-id", msg.GetRecordingId()).Msg("session recording message processing failed")
			return err
		}
		if resp != nil {
			if err := t.Send(ctx, resp); err != nil {
				log.Ctx(ctx).Err(err).Str("recording-id", msg.GetRecordingId()).Msg("failed to send response to session recording metadata client")
				return err
			}
		}
	}
}

func validateMetadata(md *recording.RecordingMetadata) error {
	if md == nil {
		return fmt.Errorf("%w: metadata is nil", ErrInvalidMetadata)
	}
	if md.GetRecordingType() == recording.RecordingFormat_RecordingFormatUnknown {
		return fmt.Errorf("%w: invalid recording type: %s", ErrInvalidMetadata, md.GetRecordingType().String())
	}
	if md.GetMetadata().GetValue() == nil {
		return ErrMetadataEmpty
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

func errorStatus(err error) *rpcstatus.Status {
	if err == nil {
		return nil
	}
	code := codes.Internal
	switch {
	case errors.Is(err, ErrMissingMetadata),
		errors.Is(err, blob.ErrChunkGap),
		errors.Is(err, blob.ErrMetadataMismatch),
		errors.Is(err, blob.ErrChunkWriteConflict),
		errors.Is(err, blob.ErrAlreadyFinalized):
		code = codes.FailedPrecondition
	case errors.Is(err, ErrInvalidMetadata),
		errors.Is(err, ErrMetadataEmpty),
		errors.Is(err, ErrMissingRecordingID):
		code = codes.InvalidArgument
	case errors.Is(err, ErrChunkTooLarge):
		code = codes.Aborted
	case errors.Is(err, ErrChecksumMismatch):
		code = codes.DataLoss
	}
	return &rpcstatus.Status{
		Code:    int32(code),
		Message: err.Error(),
	}
}
