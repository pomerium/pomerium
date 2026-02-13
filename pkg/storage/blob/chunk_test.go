package blob

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thanos-io/objstore"
)

func TestChunkReaderWriter(t *testing.T) {
	t.Parallel()

	setup := func(t *testing.T) (context.Context, ChunkWriter, ChunkReader) {
		t.Helper()
		bucket := objstore.NewInMemBucket()
		basePath := t.Name()
		ctx := t.Context()

		rw, err := newChunkReaderWriter(ctx, basePath, bucket)
		require.NoError(t, err)

		return ctx, rw.Writer(), rw.Reader()
	}

	t.Run("write and read single chunk", testWriteAndReadSingleChunk(setup))
	t.Run("write and read multiple chunks", testWriteAndReadMultipleChunks(setup))
	t.Run("chunks iterator yields in order", testChunksIteratorOrder(setup))
	t.Run("chunks iterator early break", testChunksIteratorEarlyBreak(setup))
	t.Run("empty manifest", testEmptyManifest(setup))
	t.Run("writer resumes from existing manifest", testWriterResumesFromManifest(setup))
}

type setupFunc = func(t *testing.T) (context.Context, ChunkWriter, ChunkReader)

func writeTestChunk(t *testing.T, w ChunkWriter, data []byte) {
	t.Helper()
	checksum := sha256.Sum256(data)
	require.NoError(t, w.WriteChunk(t.Context(), data, checksum))
}

func testWriteAndReadSingleChunk(setup setupFunc) func(t *testing.T) {
	return func(t *testing.T) {
		ctx, writer, reader := setup(t)

		data := []byte("hello world")
		writeTestChunk(t, writer, data)
		require.NoError(t, writer.Finalize(ctx))

		size, err := reader.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, uint64(len(data)), size)
		got, err := reader.GetAll(ctx)
		require.NoError(t, err)
		assert.Equal(t, data, got)
	}
}

func contentLen(c [][]byte) uint64 {
	size := uint64(0)
	for _, b := range c {
		size += uint64(len(b))
	}
	return size
}

func testWriteAndReadMultipleChunks(setup setupFunc) func(t *testing.T) {
	return func(t *testing.T) {
		ctx, writer, reader := setup(t)

		chunks := [][]byte{
			[]byte("foo"),
			[]byte("bar"),
			[]byte("baz"),
		}
		for _, c := range chunks {
			writeTestChunk(t, writer, c)
		}
		require.NoError(t, writer.Finalize(ctx))

		size, err := reader.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, contentLen(chunks), size)
		got, err := reader.GetAll(ctx)
		require.NoError(t, err)
		assert.Equal(t, []byte("foobarbaz"), got)
	}
}

func testChunksIteratorOrder(setup setupFunc) func(t *testing.T) {
	return func(t *testing.T) {
		ctx, writer, reader := setup(t)

		chunks := [][]byte{
			[]byte("aaa"),
			[]byte("bbb"),
			[]byte("ccc"),
		}
		for _, c := range chunks {
			writeTestChunk(t, writer, c)
		}
		require.NoError(t, writer.Finalize(ctx))

		var got [][]byte
		for data, err := range reader.Chunks(ctx) {
			require.NoError(t, err)
			got = append(got, data)
		}
		require.Len(t, got, 3)
		size, err := reader.Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, contentLen(chunks), size)
		assert.ElementsMatch(t, chunks, got)
	}
}

func testChunksIteratorEarlyBreak(setup setupFunc) func(t *testing.T) {
	return func(t *testing.T) {
		ctx, writer, reader := setup(t)

		for i := range 5 {
			writeTestChunk(t, writer, []byte{byte(i)})
		}
		require.NoError(t, writer.Finalize(ctx))

		count := 0
		for _, err := range reader.Chunks(ctx) {
			require.NoError(t, err)
			count++
			if count == 2 {
				break
			}
		}
		assert.Equal(t, 2, count)
	}
}

func testEmptyManifest(setup setupFunc) func(t *testing.T) {
	return func(t *testing.T) {
		ctx, _, reader := setup(t)

		_, err := reader.Size(ctx)
		assert.Error(t, err, "size should error when no manifest exists")

		_, err = reader.GetAll(ctx)
		assert.Error(t, err, "get all should error when no manifest exists")

		for _, err := range reader.Chunks(ctx) {
			assert.Error(t, err, "chunks should yield error when no manifest exists")
		}
	}
}

func testWriterResumesFromManifest(_ setupFunc) func(t *testing.T) {
	return func(t *testing.T) {
		bucket := objstore.NewInMemBucket()
		basePath := t.Name()
		ctx := t.Context()

		chunks := [][]byte{
			[]byte("foo"),
			[]byte("bar"),
			[]byte("baz"),
		}

		// First writer writes two chunks.
		rw1, err := newChunkReaderWriter(ctx, basePath, bucket)
		require.NoError(t, err)
		writeTestChunk(t, rw1.Writer(), chunks[0])
		writeTestChunk(t, rw1.Writer(), chunks[1])
		require.NoError(t, rw1.Writer().Finalize(ctx))

		s1, err := rw1.Reader().Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, contentLen(chunks[:2]), s1)
		got1, err := rw1.Reader().GetAll(ctx)
		require.NoError(t, err)
		assert.Equal(t, []byte("foobar"), got1)

		// Second writer picks up from existing manifest and appends.
		rw2, err := newChunkReaderWriter(ctx, basePath, bucket)
		require.NoError(t, err)
		writeTestChunk(t, rw2.Writer(), chunks[2])
		require.NoError(t, rw2.Writer().Finalize(ctx))

		got2, err := rw2.Reader().GetAll(ctx)
		require.NoError(t, err)
		assert.Equal(t, []byte("foobarbaz"), got2)
		s2, err := rw2.Reader().Size(ctx)
		require.NoError(t, err)
		assert.Equal(t, contentLen(chunks), s2)
	}
}
