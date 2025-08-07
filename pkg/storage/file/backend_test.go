package file_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	databrokerpb "github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/protoutil"
	"github.com/pomerium/pomerium/pkg/storage"
	"github.com/pomerium/pomerium/pkg/storage/file"
	"github.com/pomerium/pomerium/pkg/storage/storagetest"
)

func TestBackend(t *testing.T) {
	backend := file.New("memory://")
	storagetest.TestBackend(t, backend)
}

func BenchmarkGet(b *testing.B) {
	dir := b.TempDir()
	backend := file.New("file://" + dir)
	b.Cleanup(func() {
		_ = backend.Close()
		os.RemoveAll(dir)
	})

	data := protoutil.NewAnyString(strings.Repeat("x", 1024))
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
	backend := file.New("file://" + dir)
	b.Cleanup(func() {
		_ = backend.Close()
		os.RemoveAll(dir)
	})

	data := protoutil.NewAnyString(strings.Repeat("x", 1024))
	for b.Loop() {
		_, err := backend.Put(b.Context(), []*databrokerpb.Record{
			{Type: "example", Id: uuid.NewString(), Data: data},
		})
		require.NoError(b, err)
	}
}

func BenchmarkSyncLatestWithFilter(b *testing.B) {
	dir := b.TempDir()
	backend := file.New("file://" + dir)
	b.Cleanup(func() {
		_ = backend.Close()
		os.RemoveAll(dir)
	})

	data := protoutil.NewAnyString(strings.Repeat("x", 1024))
	for i := range 1024 {
		_, err := backend.Put(b.Context(), []*databrokerpb.Record{
			{Type: fmt.Sprintf("example-%d", i%16), Id: fmt.Sprintf("id-%d", i), Data: data},
		})
		require.NoError(b, err)
	}

	b.ResetTimer()
	for b.Loop() {
		serverVersion, recordVersion, seq, err := backend.SyncLatest(b.Context(), "example-0", storage.OrFilterExpression{
			storage.EqualsFilterExpression{Fields: []string{"id"}, Value: "id-0"},
			storage.EqualsFilterExpression{Fields: []string{"$index"}, Value: "127.0.0.1"},
		})
		if assert.NoError(b, err) {
			assert.NotZero(b, serverVersion)
			assert.NotZero(b, recordVersion)
			records, err := storage.RecordIteratorToList(seq)
			assert.NoError(b, err)
			assert.NotEmpty(b, records)
		}
	}
}
