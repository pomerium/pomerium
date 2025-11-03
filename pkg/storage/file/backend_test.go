package file_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/protobuf/types/known/structpb"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/iterutil"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/file"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestBackend(t *testing.T) {
	t.Parallel()

	backend := file.New(noop.NewTracerProvider(), "memory://")
	storagetest.TestBackend(t, backend)
}

func TestIndexing(t *testing.T) {
	t.Parallel()
	backend := file.New(noop.NewTracerProvider(), "memory://")
	storagetest.TestIndexing(t, backend)
}

func TestFilter(t *testing.T) {
	t.Parallel()
	backend := file.New(noop.NewTracerProvider(), "memory://")
	storagetest.TestFilter(t, backend)
}

func TestSyncOldRecords(t *testing.T) {
	t.Parallel()
	backend := file.New(noop.NewTracerProvider(), "memory://")
	storagetest.TestSyncOldRecords(t, backend)
}

func TestClear(t *testing.T) {
	t.Parallel()
	backend := file.New(noop.NewTracerProvider(), "memory://")
	storagetest.TestClear(t, backend)
}

func BenchmarkGet(b *testing.B) {
	dir := b.TempDir()
	backend := file.New(noop.NewTracerProvider(), "file://"+dir)
	b.Cleanup(func() {
		_ = backend.Close()
		os.RemoveAll(dir)
	})

	data := protoutil.NewAnyString(strings.Repeat("x", 128))
	for i := range 1024 {
		_, err := backend.Put(b.Context(), []*databrokerpb.Record{
			{Type: "example", Id: fmt.Sprintf("id-%d", i), Data: data},
		})
		require.NoError(b, err)
	}

	b.ResetTimer()
	for b.Loop() {
		record, err := backend.Get(b.Context(), "example", "id-500")
		if assert.NoError(b, err) {
			assert.Equal(b, "id-500", record.GetId())
		}
	}
}

func BenchmarkPut(b *testing.B) {
	dir := b.TempDir()
	backend := file.New(noop.NewTracerProvider(), "file://"+dir)
	b.Cleanup(func() {
		_ = backend.Close()
		os.RemoveAll(dir)
	})
	storagetest.BenchmarkPut(b, backend)
	b.StopTimer()
	b.ReportMetric(float64(dirSize(b, dir))/float64(b.N), "disk/op")
}

func BenchmarkPutMemory(b *testing.B) {
	dir := b.TempDir()
	backend := file.New(noop.NewTracerProvider(), "memory://")
	b.Cleanup(func() {
		_ = backend.Close()
		os.RemoveAll(dir)
	})
	storagetest.BenchmarkPut(b, backend)
}

func BenchmarkSyncLatestWithFilter(b *testing.B) {
	dir := b.TempDir()
	backend := file.New(noop.NewTracerProvider(), "file://"+dir)
	b.Cleanup(func() {
		_ = backend.Close()
		os.RemoveAll(dir)
	})

	s, err := structpb.NewStruct(map[string]any{
		"$index": map[string]any{
			"cidr": "192.168.0.0/16",
		},
	})
	require.NoError(b, err)
	for i := range 1024 {
		data := protoutil.NewAnyString("xxx")
		if i == 0 {
			data = protoutil.NewAny(s)
		}
		_, err := backend.Put(b.Context(), []*databrokerpb.Record{
			{Type: fmt.Sprintf("example-%d", i%16), Id: fmt.Sprintf("id-%d", i), Data: data},
		})
		require.NoError(b, err)
	}
	b.ResetTimer()

	b.Run("by id", func(b *testing.B) {
		for b.Loop() {
			serverVersion, recordVersion, seq, err := backend.SyncLatest(b.Context(), "example-0",
				storage.EqualsFilterExpression{Fields: []string{"id"}, Value: "id-0"})
			if assert.NoError(b, err) {
				assert.NotZero(b, serverVersion)
				assert.NotZero(b, recordVersion)
				records, err := iterutil.CollectWithError(seq)
				assert.NoError(b, err)
				assert.NotEmpty(b, records)
			}
		}
	})
	b.Run("by index", func(b *testing.B) {
		for b.Loop() {
			serverVersion, recordVersion, seq, err := backend.SyncLatest(b.Context(), "example-0",
				storage.EqualsFilterExpression{Fields: []string{"$index"}, Value: "192.168.0.1"})
			if assert.NoError(b, err) {
				assert.NotZero(b, serverVersion)
				assert.NotZero(b, recordVersion)
				records, err := iterutil.CollectWithError(seq)
				assert.NoError(b, err)
				assert.NotEmpty(b, records)
			}
		}
	})
	b.Run("id or index", func(b *testing.B) {
		for b.Loop() {
			serverVersion, recordVersion, seq, err := backend.SyncLatest(b.Context(), "example-0", storage.OrFilterExpression{
				storage.EqualsFilterExpression{Fields: []string{"id"}, Value: "id-0"},
				storage.EqualsFilterExpression{Fields: []string{"$index"}, Value: "192.168.0.1"},
			})
			if assert.NoError(b, err) {
				assert.NotZero(b, serverVersion)
				assert.NotZero(b, recordVersion)
				records, err := iterutil.CollectWithError(seq)
				assert.NoError(b, err)
				assert.NotEmpty(b, records)
			}
		}
	})
}

func dirSize(tb testing.TB, path string) int64 {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
		}
		return err
	})
	require.NoError(tb, err)
	return size
}
