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
	"github.com/pomerium/pomerium/pkg/iterutil"
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
	backend := file.New("file://" + dir)
	b.Cleanup(func() {
		_ = backend.Close()
		os.RemoveAll(dir)
	})

	data := protoutil.NewAnyString(strings.Repeat("x", 128))
	run := func(b *testing.B, cnt int) {
		b.Helper()

		buf := make([]*databrokerpb.Record, 0, cnt)
		for b.Loop() {
			buf = append(buf, &databrokerpb.Record{Type: "example", Id: uuid.NewString(), Data: data})
			if len(buf) == cnt {
				_, err := backend.Put(b.Context(), buf)
				require.NoError(b, err)
				buf = buf[:0]
			}
		}
	}

	b.Run("1", func(b *testing.B) {
		run(b, 1)
	})
	b.Run("8", func(b *testing.B) {
		run(b, 8)
	})
	b.Run("16", func(b *testing.B) {
		run(b, 16)
	})
	b.Run("32", func(b *testing.B) {
		run(b, 32)
	})
	b.Run("64", func(b *testing.B) {
		run(b, 64)
	})
}

func BenchmarkSyncLatestWithFilter(b *testing.B) {
	dir := b.TempDir()
	backend := file.New("file://" + dir)
	b.Cleanup(func() {
		_ = backend.Close()
		os.RemoveAll(dir)
	})

	data := protoutil.NewAnyString(strings.Repeat("x", 128))
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
			records, err := iterutil.CollectWithError(seq)
			assert.NoError(b, err)
			assert.NotEmpty(b, records)
		}
	}
}
