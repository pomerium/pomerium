package recording

import (
	"encoding/binary"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestPipeIPC(t *testing.T) {
	pipeIPC, err := NewPipeIPC(nil, "")
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, pipeIPC.Close())
	})

	protoData := &recording.RecordingData{
		RecordingId: "hello",
		Data: &recording.RecordingData_Metadata{
			Metadata: &recording.RecordingMetadata{
				RecordingType: recording.RecordingFormat_RecordingFormatSSH,
			},
		},
	}

	data, err := proto.Marshal(protoData)
	require.NoError(t, err)
	var lenBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(lenBuf[:], uint64(len(data)))

	_, err = pipeIPC.uploadWrite.Write(lenBuf[:n])
	require.NoError(t, err)

	_, err = pipeIPC.uploadWrite.Write(data)
	require.NoError(t, err)

	msg, err := pipeIPC.recvRecordingMsg()
	require.NoError(t, err)
	assert.Empty(t, cmp.Diff(msg, protoData, protocmp.Transform()))

	sessionResume := &recording.RecordingSession{
		Manifest: &recording.ChunkManifest{
			Items: []*recording.ChunkMetadata{
				{
					Size:     123,
					Checksum: []byte("foo"),
				},
			},
		},
	}
	require.NoError(t, pipeIPC.sendServerManifest(sessionResume), err)

}
