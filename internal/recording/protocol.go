package recording

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"

	gblob "gocloud.dev/blob"
	"gocloud.dev/gcerrors"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"

	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/ipc"
	"github.com/pomerium/pomerium/pkg/nullable"
	"github.com/pomerium/pomerium/pkg/storage/blob"
	"github.com/pomerium/pomerium/pkg/storage/blob/middleware"
)

var (
	magicBytesIn  = []byte{0xFF, 0xFF, 0xFF, 0xFF}
	magicBytesOut = []byte{0xDD, 0xDD, 0xDD, 0xDD}
)

const maxChunkSize = 1024 * 1024 * 4

var (
	ErrMissingMetadata          = errors.New("first message for a recording must contain metadata")
	ErrInvalidMetadata          = errors.New("invalid metadata")
	ErrMetadataEmpty            = errors.New("metadata any value is empty")
	ErrMissingRecordingID       = errors.New("message is missing a recording id")
	ErrChunkTooLarge            = errors.New("chunk exceeds max size")
	ErrChecksumMismatch         = errors.New("checksum did not match")
	ErrUnflushedChunks          = errors.New("cannot finalize recording: unflushed chunks")
	ErrUnknownRecordingDataType = errors.New("unknown recording data type")
)

// recordingState is the per-id slice of writer state kept by a handler.
// A single transport can interleave messages for multiple recording ids,
// so state is keyed by recording_id.
type recordingState struct {
	cw           blob.ChunkWriter
	metadataSent bool
	accumulated  []byte
}

// Handler implements the session recording upload protocol.
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
type Handler struct {
	bucket        atomic.Pointer[gblob.Bucket]
	managedPrefix atomic.Pointer[string]

	mu       sync.Mutex
	ready    *sync.Cond
	states   map[string]*recordingState
	identity string
}

var _ ipc.ServerHandler[*recording.RecordingData, *recording.RecordingCheckpoint] = (*Handler)(nil)

func newHandler(identity string) *Handler {
	h := &Handler{
		identity: identity,
		states:   make(map[string]*recordingState),
	}
	h.ready = sync.NewCond(&h.mu)
	return h
}

func (h *Handler) bucketInitialized() bool {
	b := h.bucket.Load()
	p := h.managedPrefix.Load()
	return b != nil && p != nil && *p != ""
}

func (h *Handler) waitForInit(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.bucketInitialized() {
		return nil
	}
	stop := context.AfterFunc(ctx, func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.ready.Broadcast()
	})
	defer stop()
	for !h.bucketInitialized() {
		if err := ctx.Err(); err != nil {
			return err
		}
		h.ready.Wait()
	}
	return nil
}

func (h *Handler) SendHandshake(ctx context.Context, wr io.Writer) error {
	if err := h.waitForInit(ctx); err != nil {
		return err
	}
	_, err := wr.Write(magicBytesOut)
	return err
}

func (h *Handler) RecvHandshake(_ context.Context, rd io.Reader) error {
	readBuf := [4]byte{}
	_, err := io.ReadFull(rd, readBuf[:])
	if err != nil {
		return err
	}
	if !bytes.Equal(readBuf[:], magicBytesIn) {
		return fmt.Errorf("handshake did not match")
	}
	return nil
}

func (h *Handler) OnChange(ctx context.Context, bucket *gblob.Bucket, managedPrefix string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	curBucket := h.bucket.Load()
	curPrefix := h.managedPrefix.Load()
	var curPrefixStr string
	if curPrefix != nil {
		curPrefixStr = *curPrefix
	}
	if curBucket == bucket && curPrefixStr == managedPrefix {
		log.Ctx(ctx).Debug().Msg("handler: OnChange no-op, config unchanged")
		return
	}
	if curPrefixStr != "" && managedPrefix == "" {
		log.Ctx(ctx).Error().Msg("setting managed prefixed to '' when it has been initialized is not valid")
	}

	log.Ctx(ctx).Debug().
		Str("managed-prefix", managedPrefix).
		Int("inflight-recordings", len(h.states)).
		Msg("handler: config changed, clearing recording states")
	h.bucket.Store(bucket)
	h.managedPrefix.Store(&managedPrefix)
	h.clearStatesLocked()

	if bucket != nil && managedPrefix != "" {
		h.ready.Broadcast()
	}
}

func (h *Handler) checkLimits(chunk []byte) error {
	if len(chunk) > maxChunkSize {
		return ErrChunkTooLarge
	}
	return nil
}

func validateRecordingData(msg *recording.RecordingData) error {
	if msg.GetRecordingId() == "" {
		return ErrMissingRecordingID
	}
	switch msg.Data.(type) {
	case *recording.RecordingData_Metadata,
		*recording.RecordingData_Chunk,
		*recording.RecordingData_ChunkMetadata,
		*recording.RecordingData_Trailer:
		return nil
	default:
		return fmt.Errorf("%w: %T", ErrUnknownRecordingDataType, msg.Data)
	}
}

func (h *Handler) handlerInner(ctx context.Context, msg *recording.RecordingData) (*recording.RecordingCheckpoint, error) {
	ctx = middleware.ContextWithBlobUserAgent(ctx, h.identity)
	if err := validateRecordingData(msg); err != nil {
		log.Ctx(ctx).Debug().Err(err).Msg("handler: invalid recording data")
		return &recording.RecordingCheckpoint{RecordingId: msg.GetRecordingId(), Status: errorStatus(err)}, nil
	}
	id := msg.GetRecordingId()
	switch d := msg.Data.(type) {
	case *recording.RecordingData_Metadata:
		log.Ctx(ctx).Trace().Msg("handler: dispatching metadata")
		return h.onMetadata(ctx, id, d.Metadata), nil
	case *recording.RecordingData_Chunk:
		log.Ctx(ctx).Trace().Int("chunk-bytes", len(d.Chunk)).Msg("handler: dispatching chunk")
		return h.onChunk(ctx, id, d.Chunk), nil
	case *recording.RecordingData_ChunkMetadata:
		log.Ctx(ctx).Trace().Msg("handler: dispatching checksum")
		return h.onChecksum(ctx, id, d.ChunkMetadata.GetChecksum()), nil
	case *recording.RecordingData_Trailer:
		log.Ctx(ctx).Trace().Msg("handler: dispatching trailer")
		return h.onTrailer(ctx, id, d.Trailer), nil
	default:
		panic(fmt.Sprintf("%s: %T", ErrUnknownRecordingDataType, msg.Data))
	}
}

// Implements the recording protocol / proto pipe server handler
func (h *Handler) Handler(ctx context.Context, msg *recording.RecordingData) (nullable.Value[*recording.RecordingCheckpoint], error) {
	resp, err := h.handlerInner(ctx, msg)
	if err != nil || resp == nil {
		return nullable.Value[*recording.RecordingCheckpoint]{}, err
	}
	return nullable.From(resp), nil
}

func (h *Handler) onMetadata(ctx context.Context, id string, md *recording.RecordingMetadata) *recording.RecordingCheckpoint {
	if err := validateMetadata(md); err != nil {
		log.Ctx(ctx).Debug().Err(err).Msg("onMetadata: invalid metadata")
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(err)}
	}
	st, err := h.openWriter(ctx, id, md.GetRecordingType())
	if err != nil {
		log.Ctx(ctx).Err(err).Msg("onMetadata: failed to open chunk writer")
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(err)}
	}
	if err := st.cw.WriteMetadata(ctx, md); err != nil {
		log.Ctx(ctx).Err(err).Msg("onMetadata: failed to write metadata to blob storage")
		return &recording.RecordingCheckpoint{
			RecordingId: id,
			Manifest:    st.cw.CurrentManifest(),
			Status:      errorStatus(err),
		}
	}
	st.metadataSent = true
	log.Ctx(ctx).Debug().Msg("onMetadata: metadata written, returning manifest")
	return &recording.RecordingCheckpoint{RecordingId: id, Manifest: st.cw.CurrentManifest()}
}

func (h *Handler) onChunk(ctx context.Context, id string, data []byte) *recording.RecordingCheckpoint {
	if err := h.checkLimits(data); err != nil {
		log.Ctx(ctx).Debug().Err(err).Int("chunk-bytes", len(data)).Msg("onChunk: single chunk exceeds size limit")
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(err)}
	}
	st, ok := h.getState(id)
	if !ok || !st.metadataSent {
		log.Ctx(ctx).Debug().Bool("known-id", ok).Msg("onChunk: chunk received before metadata")
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(ErrMissingMetadata)}
	}
	st.accumulated = append(st.accumulated, data...)
	if err := h.checkLimits(st.accumulated); err != nil {
		log.Ctx(ctx).Debug().Err(err).Int("accumulated-bytes", len(st.accumulated)).Msg("onChunk: accumulated chunk exceeds size limit")
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(err)}
	}
	log.Ctx(ctx).Debug().Int("accumulated-bytes", len(st.accumulated)).Msg("onChunk: chunk accumulated, awaiting checksum")
	return nil
}

func (h *Handler) onChecksum(ctx context.Context, id string, checksum []byte) *recording.RecordingCheckpoint {
	st, ok := h.getState(id)
	if !ok || !st.metadataSent {
		log.Ctx(ctx).Trace().Bool("known-id", ok).Msg("onChecksum: checksum received before metadata")
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(ErrMissingMetadata)}
	}
	var incoming [16]byte
	copy(incoming[:], checksum)
	if !checkMd5(incoming, st.accumulated) {
		log.Ctx(ctx).Trace().Int("accumulated-bytes", len(st.accumulated)).Msg("onChecksum: checksum mismatch")
		return &recording.RecordingCheckpoint{
			RecordingId: id,
			Manifest:    st.cw.CurrentManifest(),
			Status:      errorStatus(ErrChecksumMismatch),
		}
	}
	if err := st.cw.WriteChunk(ctx, st.accumulated, incoming); err != nil {
		log.Ctx(ctx).Err(err).Msg("onChecksum: failed to write chunk to blob storage")
		return &recording.RecordingCheckpoint{
			RecordingId: id,
			Manifest:    st.cw.CurrentManifest(),
			Status:      errorStatus(err),
		}
	}
	flushed := len(st.accumulated)
	st.accumulated = st.accumulated[:0]
	log.Ctx(ctx).Trace().Int("flushed-bytes", flushed).Msg("onChecksum: chunk flushed to blob storage")
	return &recording.RecordingCheckpoint{RecordingId: id, Manifest: st.cw.CurrentManifest()}
}

func (h *Handler) onTrailer(ctx context.Context, id string, trailer *recording.RecordingTrailer) *recording.RecordingCheckpoint {
	st, ok := h.getState(id)
	if !ok {
		log.Ctx(ctx).Trace().Msg("onTrailer: trailer received before metadata")
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(ErrMissingMetadata)}
	}
	if len(st.accumulated) > 0 {
		log.Ctx(ctx).Trace().Int("accumulated-bytes", len(st.accumulated)).Msg("onTrailer: trailer received with unflushed chunks")
		return &recording.RecordingCheckpoint{RecordingId: id, Status: errorStatus(ErrUnflushedChunks)}
	}

	if err := st.cw.Finalize(ctx, trailer); err != nil {
		log.Ctx(ctx).Debug().Err(err).Msg("onTrailer: failed to finalize recording")
		return &recording.RecordingCheckpoint{
			RecordingId: id,
			Manifest:    st.cw.CurrentManifest(),
			Status:      errorStatus(err),
		}
	}
	manifest := st.cw.CurrentManifest()
	h.deleteState(id)
	log.Ctx(ctx).Debug().Msg("onTrailer: recording finalized, state evicted")
	return &recording.RecordingCheckpoint{RecordingId: id, Manifest: manifest}
}

// openWriter lazily opens a chunkWriter
func (h *Handler) openWriter(ctx context.Context, id string, fmtType recording.RecordingFormat) (*recordingState, error) {
	if st, ok := h.getState(id); ok {
		log.Ctx(ctx).Debug().Msg("openWriter: reusing existing chunk writer state")
		return st, nil
	}
	cw, err := blob.NewChunkWriter(ctx, blob.SchemaV1WithKey{
		SchemaV1: blob.SchemaV1{
			ClusterID:     *h.managedPrefix.Load(),
			RecordingType: string(convertFormat(fmtType)),
		},
		Key: id,
	}, h.bucket.Load())
	if err != nil {
		log.Ctx(ctx).Err(err).Msg("openWriter: failed to open new chunk writer")
		return nil, err
	}
	st := &recordingState{
		cw:           cw,
		metadataSent: cw.CurrentMetadata() != nil,
	}
	h.setState(id, st)
	log.Ctx(ctx).Trace().Bool("resuming", st.metadataSent).Msg("openWriter: opened new chunk writer")
	return st, nil
}

func (h *Handler) getState(id string) (*recordingState, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	ret, ok := h.states[id]
	return ret, ok
}

func (h *Handler) setState(id string, st *recordingState) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.states[id] = st
}

func (h *Handler) deleteState(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.states, id)
}

func (h *Handler) clearStatesLocked() {
	clear(h.states)
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
	return &rpcstatus.Status{
		Code:    int32(errorCode(err)),
		Message: err.Error(),
	}
}

func errorCode(err error) codes.Code {
	switch {
	case errors.Is(err, ErrMissingMetadata),
		errors.Is(err, blob.ErrChunkGap),
		errors.Is(err, blob.ErrMetadataMismatch),
		errors.Is(err, blob.ErrChunkWriteConflict),
		errors.Is(err, blob.ErrAlreadyFinalized):
		return codes.FailedPrecondition
	case errors.Is(err, ErrInvalidMetadata),
		errors.Is(err, ErrMetadataEmpty),
		errors.Is(err, ErrMissingRecordingID),
		errors.Is(err, ErrUnknownRecordingDataType):
		return codes.InvalidArgument
	case errors.Is(err, ErrChunkTooLarge):
		return codes.ResourceExhausted
	case errors.Is(err, ErrChecksumMismatch):
		return codes.DataLoss
	}
	switch gcerrors.Code(err) {
	case gcerrors.Canceled, gcerrors.DeadlineExceeded, gcerrors.Unknown:
		// not a blob storage error
	default:
		return codes.Unavailable
	}
	return codes.Internal
}
