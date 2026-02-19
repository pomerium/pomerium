package log

import (
	"fmt"
	"sync"
	"testing"
)

func makeAuthorizeLog(path string) []byte {
	return []byte(fmt.Sprintf(
		`{"level":"info","service":"authorize","message":"authorize check","method":"GET","path":"%s"}`,
		path,
	))
}

func makeEnvoyLog(path string) []byte {
	return []byte(fmt.Sprintf(
		`{"level":"info","service":"envoy","message":"http-request","method":"GET","path":"%s"}`,
		path,
	))
}

func makeUnrelatedLog() []byte {
	return []byte(`{"level":"info","service":"proxy","message":"starting server"}`)
}

func TestRingBuffer_BasicWriteAndFlush(t *testing.T) {
	rb := NewRingBuffer()

	rb.Write(makeAuthorizeLog("/a"))
	rb.Write(makeEnvoyLog("/b"))

	if rb.Count() != 2 {
		t.Fatalf("expected 2 entries, got %d", rb.Count())
	}

	entries := rb.Flush()
	if len(entries) != 2 {
		t.Fatalf("expected 2 flushed entries, got %d", len(entries))
	}

	if rb.Count() != 0 {
		t.Errorf("expected 0 entries after flush, got %d", rb.Count())
	}
	if rb.BytesSinceFlush() != 0 {
		t.Errorf("expected 0 bytesSinceFlush after flush, got %d", rb.BytesSinceFlush())
	}
}

func TestRingBuffer_FilterRejectsUnrelatedLogs(t *testing.T) {
	rb := NewRingBuffer()

	rb.Write(makeUnrelatedLog())
	rb.Write([]byte(`not json`))
	rb.Write(makeAuthorizeLog("/ok"))

	if rb.Count() != 1 {
		t.Fatalf("expected 1 entry (only authorize log), got %d", rb.Count())
	}
}

func TestRingBuffer_EvictsOldestOnOverflow(t *testing.T) {
	rb := NewRingBuffer()
	rb.capacity = 300 // small capacity for testing

	// Write entries until we exceed capacity.
	for i := range 10 {
		rb.Write(makeAuthorizeLog(fmt.Sprintf("/%d", i)))
	}

	// Buffer should not exceed capacity.
	if rb.Size() > rb.capacity {
		t.Errorf("size %d exceeds capacity %d", rb.Size(), rb.capacity)
	}

	entries := rb.Flush()
	if len(entries) == 0 {
		t.Fatal("expected some entries after overflow")
	}

	// The last entry should be the most recent write.
	last := string(entries[len(entries)-1])
	expected := string(makeAuthorizeLog("/9"))
	if last != expected {
		t.Errorf("last entry = %s, want %s", last, expected)
	}
}

func TestRingBuffer_FlushReturnsChronologicalOrder(t *testing.T) {
	rb := NewRingBuffer()
	rb.capacity = 500

	for i := range 5 {
		rb.Write(makeAuthorizeLog(fmt.Sprintf("/%d", i)))
	}

	entries := rb.Flush()
	for i, e := range entries {
		expected := string(makeAuthorizeLog(fmt.Sprintf("/%d", i)))
		if string(e) != expected {
			t.Errorf("entry[%d] = %s, want %s", i, string(e), expected)
		}
	}
}

func TestRingBuffer_SamplingAfterThreshold(t *testing.T) {
	rb := NewRingBuffer()
	rb.samplingThreshold = 100 // low threshold for testing
	rb.samplingRate = 0.05

	// Always reject in sampling mode.
	rb.randFunc = func() float64 { return 0.5 }

	// Write enough to exceed threshold.
	for range 5 {
		rb.Write(makeAuthorizeLog("/fill"))
	}

	countBeforeSampling := rb.Count()

	// These should all be rejected (rand returns 0.5 >= 0.05).
	for range 100 {
		rb.Write(makeAuthorizeLog("/sampled"))
	}

	if rb.Count() != countBeforeSampling {
		t.Errorf("expected no new entries after sampling rejection, got %d (was %d)",
			rb.Count(), countBeforeSampling)
	}
}

func TestRingBuffer_SamplingAcceptsAtRate(t *testing.T) {
	rb := NewRingBuffer()
	rb.samplingThreshold = 100
	rb.samplingRate = 0.05

	// Always accept in sampling mode.
	rb.randFunc = func() float64 { return 0.01 }

	// Fill past threshold.
	for range 5 {
		rb.Write(makeAuthorizeLog("/fill"))
	}

	countAfterFill := rb.Count()

	// These should all be accepted (rand returns 0.01 < 0.05).
	rb.Write(makeAuthorizeLog("/accepted"))

	if rb.Count() != countAfterFill+1 {
		t.Errorf("expected entry to be accepted, count = %d (was %d)",
			rb.Count(), countAfterFill)
	}
}

func TestRingBuffer_FlushResetsSamplingCounter(t *testing.T) {
	rb := NewRingBuffer()
	rb.samplingThreshold = 100
	rb.samplingRate = 0.05

	// Always reject in sampling mode.
	rb.randFunc = func() float64 { return 0.5 }

	// Fill past threshold.
	for range 5 {
		rb.Write(makeAuthorizeLog("/fill"))
	}

	if rb.BytesSinceFlush() < rb.samplingThreshold {
		t.Fatal("expected to be past sampling threshold")
	}

	// Flush resets counter.
	rb.Flush()

	if rb.BytesSinceFlush() != 0 {
		t.Errorf("expected 0 bytesSinceFlush after flush, got %d", rb.BytesSinceFlush())
	}

	// Should be back to 100% capture.
	rb.Write(makeAuthorizeLog("/afterflush"))
	if rb.Count() != 1 {
		t.Errorf("expected 1 entry after flush (100%% capture), got %d", rb.Count())
	}
}

func TestRingBuffer_EmptyFlush(t *testing.T) {
	rb := NewRingBuffer()
	entries := rb.Flush()
	if entries != nil {
		t.Errorf("expected nil from empty flush, got %v", entries)
	}
}

func TestRingBuffer_ThreadSafety(t *testing.T) {
	rb := NewRingBuffer()
	rb.capacity = 10000

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 100 {
				rb.Write(makeAuthorizeLog(fmt.Sprintf("/%d/%d", i, j)))
			}
		}()
	}

	// Concurrent flushes.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 5 {
			rb.Flush()
		}
	}()

	wg.Wait()

	// Should not panic or deadlock. Final state should be consistent.
	if rb.Count() < 0 {
		t.Error("negative count")
	}
	if rb.Size() < 0 {
		t.Error("negative size")
	}
}
