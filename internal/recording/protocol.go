package recording

import (
	"context"
	//nolint:gosec
	"crypto/md5"
	"errors"
	"fmt"
	"io"
	"os"

	gblob "gocloud.dev/blob"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
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
	ErrUnflushedChunks    = errors.New("cannot finalize recording: unflushed chunks")
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
	maxChunkSize  int
}

func newHandler(bucket *gblob.Bucket, managedPrefix string, maxChunkSize int) *Handler {
	return &Handler{
		bucket:        bucket,
		managedPrefix: managedPrefix,
		states:        make(map[string]*recordingState),
		maxChunkSize:  maxChunkSize,
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

func (h *Handler) checkLimits(chunk []byte) error {
	if len(chunk) > h.maxChunkSize {
		return ErrChunkTooLarge
	}
	return nil
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
	case *recording.RecordingData_ChunkMetadata:
		return h.onChecksum(ctx, id, d.ChunkMetadata), nil
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
	if err := h.checkLimits(data); err != nil {
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(err)}
	}
	st, ok := h.states[id]
	if !ok || !st.metadataSent {
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(ErrMissingMetadata)}
	}
	st.accumulated = append(st.accumulated, data...)
	if err := h.checkLimits(st.accumulated); err != nil {
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(err)}
	}
	return nil
}

func (h *Handler) onChecksum(ctx context.Context, id string, chunkMetadata *recording.ChunkMetadata) *recording.RecordingCheckpoint {
	st, ok := h.states[id]
	if !ok || !st.metadataSent {
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(ErrMissingMetadata)}
	}
	var incoming [16]byte
	copy(incoming[:], chunkMetadata.Checksum)
	//nolint:gosec
	actual := md5.Sum(st.accumulated)
	if actual != incoming {
		return &recording.RecordingCheckpoint{
			RecordingId: id,
			Manifest:    st.cw.CurrentManifest(),
			Status:      errorStatus(ErrChecksumMismatch),
		}
	}
	// TODO: write per chunk metadata as well
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
	if len(st.accumulated) > 0 {
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(ErrUnflushedChunks)}
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

// TODO: these need to be renamed
var ErrProtocolPermanent = errors.New("unrecoverable session recording protocol error")

type Protocol struct {
	runCtx            context.Context
	tr                TransportProtocol
	maxChunkSize      uint32
	initBucket        *gblob.Bucket
	initManagedPrefix string
}

// Run runs the session recording upload protocol.
// For each recording ID:
// Client (envoy)                     Server (pomerium-core)
//
//	│                                    │
//	├──► RecordingData(Metadata) ───────►│ 1. Receive metadata
//	│                                    │    Validate recording ID
//	│                                    │    Create chunk writer
//	│                                    │
//	│◄─── RecordingSession ──────────────┤ 2. Send manifest
//	│     (config, manifest)             │    (for resume support)
//	│                                    │
//	├──► RecordingData(Chunk) ──────────►│ 3. Stream chunks
//	├──► ...                  ──────────►│
//	├──► RecordingData(Checksum) ───────►│ 4. Verify checksum
//	│                                    │    Write accumulated chunks
//	│◄─── RecordingSession ──────────────┤ 5. Send updated manifest
//	│                                    │
//	├──► RecordingData(Chunk) ──────────►│ 6. Continue streaming until done...
//	│                                    │
//
// It's allowed to interleave recordings with different IDs, but the messages per ID must follow the strict protocol order
// outlined above.
func (p *Protocol) Run() error {
	h := newHandler(p.initBucket, p.initManagedPrefix, maxChunkSize)
	tr := p.tr
	tr.OnChange(p.initBucket, p.initManagedPrefix)
	for {
	READRETRY:
		select {
		case <-p.runCtx.Done():
			return p.runCtx.Err()
		default:
		}
		msg, err := tr.Recv(p.runCtx)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			// TODO: this is stil ugly
			shouldRetry, wrappedErr := p.handleRecvErr(err)
			if shouldRetry {
				goto READRETRY
			}
			if errors.Is(wrappedErr, ErrProtocolPermanent) {
				log.Ctx(p.runCtx).Err(err).Msg("permanent error in session recording protocol, signalling exit from all handlers")
				return wrappedErr
			}
			log.Ctx(p.runCtx).Err(err).Msg("unrecovarable erorr exiting from session recording protocol handler, other handlers will continue")
			return nil
		}
		h.OnChange(tr.currentConfig())
		resp, err := h.Step(p.runCtx, msg)
		// TODO: also ugly and doesn't handle remote blob upload errors
		switch {
		case err == nil:
			// fall through
		case errors.Is(err, io.EOF):
			return nil
		case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, os.ErrClosed):
			log.Ctx(p.runCtx).Err(err).Msg("recording transport closed unexpectedly")
			return nil
		default:
			log.Ctx(p.runCtx).Err(err).Str("recording-id", msg.GetRecordingId()).Msg("session recording message processing failed")
			return fmt.Errorf("recording transport recv : %w", err)
		}
		if resp != nil {
			if err := tr.Send(p.runCtx, resp); err != nil {
				log.Ctx(p.runCtx).Err(err).Str("recording-id", msg.GetRecordingId()).Msg("failed to send response to session recording metadata client")
				return err
			}
		}
	}
}

func (p *Protocol) handleRecvErr(err error) (shouldRetry bool, retErr error) {
	// unexpected closes
	if errors.Is(err, os.ErrClosed) {
		return false, fmt.Errorf("%w : %w", ErrProtocolPermanent, err)
	}
	// context propagation errors
	if errors.Is(err, p.runCtx.Err()) || errors.Is(err, context.Canceled) {
		return false, nil
	}
	st, ok := status.FromError(err)
	// bucket upload cancellation
	if ok && st.Code() == codes.Canceled {
		return false, nil
	}
	// pipe was flagged for reread
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true, nil
	}
	log.Ctx(p.runCtx).Err(err).Msg("failed to receive message from session recording client")
	// TODO: handle "unhandled" errors
	panic(err)
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
