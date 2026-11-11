package databrokerutil_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/testing/protocmp"

	"github.com/pomerium/pomerium/internal/databroker"
	"github.com/pomerium/pomerium/internal/testutil"
	"github.com/pomerium/pomerium/pkg/databrokerutil"
	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
)

func TestDirectoryMirror(t *testing.T) {
	t.Parallel()

	recordType := "test-directory-mirror"

	dump := func(client databrokerpb.DataBrokerServiceClient) []*databrokerpb.File {
		t.Helper()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()

		var files []*databrokerpb.File
		stream, err := client.SyncLatest(ctx, &databrokerpb.SyncLatestRequest{
			Type: recordType,
		})
		require.NoError(t, err)
		for {
			res, err := stream.Recv()
			if errors.Is(err, io.EOF) {
				break
			}
			require.NoError(t, err)

			switch res := res.Response.(type) {
			case *databrokerpb.SyncLatestResponse_Record:
				var file databrokerpb.File
				if res.Record.Data.UnmarshalTo(&file) == nil {
					files = append(files, &file)
				}
			}
		}
		return files
	}

	t.Run("reconcile", func(t *testing.T) {
		t.Parallel()
		t.Run("local", func(t *testing.T) {
			t.Parallel()

			srv := databroker.NewBackendServer(noop.NewTracerProvider())
			t.Cleanup(srv.Stop)
			cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
				databrokerpb.RegisterDataBrokerServiceServer(s, srv)
			})
			client := databrokerpb.NewDataBrokerServiceClient(cc)

			rootDir := t.TempDir()

			require.NoError(t, os.WriteFile(filepath.Join(rootDir, "example.txt"), []byte("TEST"), 0o600))

			d := databrokerutil.NewDirectoryMirror(client, recordType, rootDir,
				databrokerutil.WithDirectoryMirrorMode(databrokerutil.DirectoryMirrorModeLocal))
			assert.NoError(t, d.Reconcile(t.Context()))
			assert.Empty(t, cmp.Diff([]*databrokerpb.File{
				{Name: "example.txt", Data: []byte("TEST")},
			}, dump(client), protocmp.Transform()))

			require.NoError(t, os.Remove(filepath.Join(rootDir, "example.txt")))
			assert.NoError(t, d.Reconcile(t.Context()))
			assert.Empty(t, dump(client))
		})
	})
	t.Run("watch", func(t *testing.T) {
		t.Parallel()

		t.Run("local", func(t *testing.T) {
			t.Parallel()

			srv := databroker.NewBackendServer(noop.NewTracerProvider())
			t.Cleanup(srv.Stop)
			cc := testutil.NewGRPCServer(t, func(s *grpc.Server) {
				databrokerpb.RegisterDataBrokerServiceServer(s, srv)
			})
			client := databrokerpb.NewDataBrokerServiceClient(cc)

			rootDir := t.TempDir()

			d := databrokerutil.NewDirectoryMirror(client, recordType, rootDir,
				databrokerutil.WithDirectoryMirrorMode(databrokerutil.DirectoryMirrorModeLocal))
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			go d.Watch(ctx)

			require.NoError(t, os.WriteFile(filepath.Join(rootDir, "example1.txt"), []byte("TEST1"), 0o600))

			assert.Eventually(t, func() bool { return len(dump(client)) == 1 }, 10*time.Second, 10*time.Millisecond)
			assert.Empty(t, cmp.Diff([]*databrokerpb.File{
				{Name: "example1.txt", Data: []byte("TEST1")},
			}, dump(client), protocmp.Transform()))

			require.NoError(t, os.WriteFile(filepath.Join(rootDir, "example2.txt"), []byte("TEST2"), 0o600))

			assert.Eventually(t, func() bool { return len(dump(client)) == 2 }, 10*time.Second, 10*time.Millisecond)
			assert.Empty(t, cmp.Diff([]*databrokerpb.File{
				{Name: "example1.txt", Data: []byte("TEST1")},
				{Name: "example2.txt", Data: []byte("TEST2")},
			}, dump(client), protocmp.Transform()))

			require.NoError(t, os.Remove(filepath.Join(rootDir, "example1.txt")))
			require.NoError(t, os.Remove(filepath.Join(rootDir, "example2.txt")))
			assert.Eventually(t, func() bool { return len(dump(client)) == 0 }, 10*time.Second, 10*time.Millisecond)
			assert.Empty(t, dump(client))
		})
	})
}
