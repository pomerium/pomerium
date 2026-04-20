package recording

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	xrecording "github.com/pomerium/envoy-custom/api/x/recording"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func TestSecuredRecordingServer(t *testing.T) {
	sharedKeyBytes := []byte("0123456789abcdef0123456789abcdef")
	sharedKeyB64 := base64.StdEncoding.EncodeToString(sharedKeyBytes)

	cfg := defaultTestConfig("file://" + t.TempDir())
	cfg.Options.SharedKey = sharedKeyB64

	srv, err := NewRecordingServer(t.Context(), cfg, TransportOptions{TransportMode: ModeGRPC, Concurrency: uint32(666)})
	require.NoError(t, err)
	secured := NewSecuredServer(t.Context(), srv, cfg)
	secured.OnConfigChange(t.Context(), cfg)

	t.Run("unauthenticated without JWT", func(t *testing.T) {
		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			xrecording.RegisterRecordingServiceServer(s, secured)
		})
		client := xrecording.NewRecordingServiceClient(cc)

		stream, connErr := client.Record(t.Context())
		require.NoError(t, connErr)

		sendErr := stream.Send(&xrecording.RecordingData{
			RecordingId: "no-jwt",
			Data: &xrecording.RecordingData_Metadata{
				Metadata: &xrecording.RecordingMetadata{
					RecordingType: xrecording.RecordingFormat_RecordingFormatSSH,
				},
			},
		})
		require.NoError(t, sendErr)

		_, recvErr := stream.Recv()
		require.Error(t, recvErr)
		assert.Equal(t, codes.Unauthenticated, status.Code(recvErr), recvErr.Error())

		_ = stream.CloseSend()
	})

	t.Run("authenticated with valid JWT", func(t *testing.T) {
		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			xrecording.RegisterRecordingServiceServer(s, secured)
		}, grpc.WithStreamInterceptor(
			grpcutil.WithStreamSignedJWT(func() []byte { return sharedKeyBytes }),
		))
		client := xrecording.NewRecordingServiceClient(cc)

		stream, err := client.Record(t.Context())
		require.NoError(t, err)

		session := sendMetadata(t, stream, "with-jwt")
		assert.NotNil(t, session.Manifest)
		_ = stream.CloseSend()
	})
}
