package databrokerutil_test

import (
	"os"
	"path/filepath"
	"testing"

	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestDirectoryMirror(t *testing.T) {
	t.Parallel()

	srv := databroker.NewBackendServer(noop.NewTracerProvider())
	t.Cleanup(srv.Stop)
	cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
		databrokerpb.RegisterDataBrokerServiceServer(s, srv)
	})
	client := databrokerpb.NewDataBrokerServiceClient(cc)

	rootDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(rootDir, "example.txt"), []byte("TEST"), 0o600))

	d := databrokerutil.NewDirectoryMirror(client, "TEST_DIRECTORY_MIRROR", rootDir)
	assert.NoError(t, d.Reconcile(t.Context()))

	require.NoError(t, os.Remove(filepath.Join(rootDir, "example.txt")))
	assert.NoError(t, d.Reconcile(t.Context()))
}
