package recording_test

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/pomerium/envoy-custom/api/x/recording"
	rec "github.com/pomerium/pomerium/internal/recording"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/grpcutil"
)

func TestSecuredRecordingServer(t *testing.T) {
	sharedKeyBytes := []byte("0123456789abcdef0123456789abcdef")
	sharedKeyB64 := base64.StdEncoding.EncodeToString(sharedKeyBytes)

	cfg := defaultTestConfig("file://" + t.TempDir())
	cfg.Options.SharedKey = sharedKeyB64

	srv := rec.NewRecordingServer(t.Context(), cfg)
	secured := rec.NewSecuredServer(srv)
	secured.OnConfigChange(t.Context(), cfg)

	t.Run("unauthenticated without JWT", func(t *testing.T) {
		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			recording.RegisterRecordingServiceServer(s, secured)
		})
		client := recording.NewRecordingServiceClient(cc)

		stream, err := client.Record(t.Context())
		require.NoError(t, err)

		err = stream.Send(&recording.RecordingData{
			Data: &recording.RecordingData_Metadata{
				Metadata: &recording.RecordingMetadata{
					Id:            "no-jwt",
					RecordingType: recording.RecordingFormat_RecordingFormatSSH,
				},
			},
		})
		if err == nil {
			_, err = stream.Recv()
		}
		require.Error(t, err)
		assert.Equal(t, codes.Unauthenticated, status.Code(err))
	})

	t.Run("authenticated with valid JWT", func(t *testing.T) {
		cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
			recording.RegisterRecordingServiceServer(s, secured)
		}, grpc.WithStreamInterceptor(
			grpcutil.WithStreamSignedJWT(func() []byte { return sharedKeyBytes }),
		))
		client := recording.NewRecordingServiceClient(cc)

		stream, err := client.Record(t.Context())
		require.NoError(t, err)

		session := sendMetadata(t, stream, "with-jwt")
		assert.NotNil(t, session.GetConfig())
	})
}
