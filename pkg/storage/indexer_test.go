package storage

import (
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func testIndexerConformance(t *testing.T, idxer Indexer) {
	t.Helper()
	t.Run("crud", func(t *testing.T) {
		testCRUD(t, idxer)
	})

	t.Run("concurrent updates", func(t *testing.T) {
		testConcurrentUpdateSingleKey(t, idxer)
	})

	t.Run("concurrent multi-key updates", func(t *testing.T) {
		testConcurrentUpdateMultiKey(t, idxer)
	})
}

func TestIndexerSimple(t *testing.T) {
	t.Parallel()
	idxer := NewSimpleIndexer()
	testIndexerConformance(t, idxer)
}

func TestIndexerFast(t *testing.T) {
	t.Parallel()
	idxer := NewFastIndexer(8)
	testIndexerConformance(t, idxer)
}

func TestIndexerBTree(t *testing.T) {
	t.Parallel()
	idxer := NewBTreeIndexer(2)
	testIndexerConformance(t, idxer)
}

func benchmarkConformance(b *testing.B, idxer Indexer) {
	b.Run("concurrent conflicts", func(b *testing.B) {
		benchmarkConcurrentConflict(b, idxer)
	})

	b.Run("concurrent updates", func(b *testing.B) {
		benchmarkConcurrentUpdates(b, idxer)
	})
}

func BenchmarkIndexerSimple(b *testing.B) {
	idxer := NewSimpleIndexer()
	benchmarkConformance(b, idxer)
}

func BenchmarkIndexerFast(b *testing.B) {
	idxer := NewFastIndexer(8)
	benchmarkConformance(b, idxer)
}

func BenchmarkIndexerBtree(b *testing.B) {
	idxer := NewBTreeIndexer(2)
	benchmarkConformance(b, idxer)
}

func benchmarkConcurrentUpdates(b *testing.B, idxer Indexer) {
	b.Helper()
	var wg sync.WaitGroup
	wg.Add(b.N)

	for i := range b.N {
		go func() {
			defer wg.Done()
			idxer.Put(strconv.Itoa(i), "a")
		}()
	}
	wg.Wait()
}

func benchmarkConcurrentConflict(b *testing.B, idxer Indexer) {
	b.Helper()
	var wg sync.WaitGroup
	wg.Add(b.N)

	for i := range b.N {
		go func() {
			defer wg.Done()
			idxer.Put("idA", strconv.Itoa(i))
		}()
	}
	wg.Wait()
}

func testCRUD(t *testing.T, idxer Indexer) {
	t.Helper()
	idxer.Put("foo", "bar")
	idxer.Put("foo", "baz")

	assert.ElementsMatch(t, idxer.List("foo"), []string{"bar", "baz"})
	assert.Equal(t, 0, len(idxer.List("bar")))

	idxer.Delete("foo", "bar")
	assert.ElementsMatch(t, idxer.List("foo"), []string{"baz"})
	idxer.Delete("foo", "baz")
	assert.Equal(t, 0, len(idxer.List("foo")))
}

func testConcurrentUpdateSingleKey(t *testing.T, idxer Indexer) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(100)
	for i := range 100 {
		go func() {
			defer wg.Done()
			idxer.Put("idA", strconv.Itoa(i))
		}()
	}
	wg.Wait()

	vals := idxer.List("idA")
	assert.Equal(t, 100, len(vals))
}

func testConcurrentUpdateMultiKey(t *testing.T, idxer Indexer) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(100)
	for i := range 10 {
		for j := range 10 {
			go func() {
				defer wg.Done()
				idxer.Put(strconv.Itoa(j), strconv.Itoa(i))
			}()
		}
	}
	wg.Wait()
	for i := range 10 {
		vals := idxer.List(strconv.Itoa(i))
		assert.Equal(t, 10, len(vals))
	}
}
