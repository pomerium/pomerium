package databroker

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/storage"
)

// TestServer_RetiredTypeCleanupDeletes drives the cleaner end to end: the TTLs
// the server builds are handed to backend.Clean, and a legacy record of the
// retired (unresolvable) type must actually be removed. The TTL is shortened so
// the freshly written record is already past it; its configured value is
// asserted separately.
func TestServer_RetiredTypeCleanupDeletes(t *testing.T) {
	t.Parallel()

	const mcpRefreshTokenTypeURL = "type.googleapis.com/oauth21.MCPRefreshToken"
	srv := newServer(t)
	_, err := srv.Put(t.Context(), &databrokerpb.PutRequest{
		Records: []*databrokerpb.Record{{
			Type: mcpRefreshTokenTypeURL,
			Id:   "legacy-token",
			Data: &anypb.Any{TypeUrl: mcpRefreshTokenTypeURL, Value: []byte{0x0a, 0x01, 'x'}},
		}},
	})
	require.NoError(t, err)

	backend, err := srv.(*backendServer).getBackend(t.Context())
	require.NoError(t, err)
	ttls := srv.(*backendServer).buildRecordTTLs(backend)
	require.Contains(t, ttls, mcpRefreshTokenTypeURL)
	assert.Equal(t, 24*time.Hour, ttls[mcpRefreshTokenTypeURL])
	ttls[mcpRefreshTokenTypeURL] = time.Nanosecond

	require.NoError(t, backend.Clean(t.Context(), storage.CleanOptions{RecordTTLs: ttls}))

	_, err = srv.Get(t.Context(), &databrokerpb.GetRequest{Type: mcpRefreshTokenTypeURL, Id: "legacy-token"})
	assert.Equal(t, codes.NotFound, status.Code(err), "the cleaner left the retired record in place")
}
